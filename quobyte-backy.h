#define OBJ_IS_ALLOCATED(bitmap, i) (bitmap[i / 8] & (1 << (i % 8)))
#define OBJ_SET_ALLOCATED(bitmap, i) (bitmap[i / 8] |= (1 << (i % 8)))

static void dump_version(FILE *fp, uint64_t *version, int count) {
    int i;
    fprintf(fp, "[ ");
    for (i = 0; i < count; i++) {
         fprintf(fp, "%s%lu" , i ? ", " : "", version[i]);
    }
    fprintf(fp, " ]");
}

struct qb_connection {
	char *path;
	struct quobyte_fh* fh;
	size_t filesize;
	char file_id[256];
	int obj_size;
	uint64_t obj_count;
	int storage_files;
	uint64_t *cur_version;
	uint64_t *min_version;
	size_t bitmap_sz;
	char *bitmap;
};

static int qb_create_adapter(FILE *log, char *registry) {
	int ret;
	struct timespec tstart={}, tend={};
	fprintf(log, "connecting to quobyte registry %s...\n", registry);
	clock_gettime(CLOCK_MONOTONIC, &tstart);
	ret = quobyte_create_adapter(registry);
	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(log, "quobyte_create_adapter took about %.5f seconds\n",
		   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
		   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	fflush(log);
	return ret;
}

static int qb_open_file(FILE *log, struct qb_connection *qb, char *path) {
	struct timespec tstart={}, tend={};
	size_t file_id_sz;
	struct stat st;
	assert (!qb->fh);
	memset(qb, 0x00, sizeof(struct qb_connection));
	clock_gettime(CLOCK_MONOTONIC, &tstart);
	qb->fh = quobyte_open(path, O_RDONLY | O_DIRECT, 0600);
	if (!qb->fh) {
		fprintf(log, "file %s open: %s (%d)\n", path, strerror(errno), errno);
		return 1;
	}
	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(log, "quobyte_open took about %.5f seconds\n",
	   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
	   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	fflush(log);

	clock_gettime(CLOCK_MONOTONIC, &tstart);
	if ((file_id_sz = quobyte_getxattr(path, "quobyte.file_id", &qb->file_id[0], sizeof(qb->file_id) - 1)) < 0) {
		fprintf(log, "file %s could not retrieve quobyte.file_id: %s (%d)\n", path, strerror(errno), errno);
		return 1;
	}
	qb->path = strdup(path);
	assert(qb->path);
	qb->file_id[file_id_sz] = 0;
	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(log, "quobyte_getxattr took about %.5f seconds\n",
	   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
	   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	fprintf(log, "quobyte.file_id is %s\n", &qb->file_id[0]);
	fflush(log);

	clock_gettime(CLOCK_MONOTONIC, &tstart);
	assert(!quobyte_fstat(qb->fh, &st));
	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(log, "quobyte_fstat took about %.5f seconds\n",
	   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
	   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	fflush(log);
	qb->filesize = st.st_size;
	fprintf(log, "filesize is %lu bytes\n", qb->filesize);
	qb->obj_size = quobyte_get_object_size(qb->fh);
	assert(qb->obj_size > 0);
	fprintf(log, "objectsize is %u bytes\n", qb->obj_size);
	qb->storage_files = quobyte_get_number_of_storage_files(qb->fh);
	assert(qb->storage_files > 0);
	fprintf(log, "number of storage files is %d\n", qb->storage_files);
	qb->obj_count = (qb->filesize + qb->obj_size - 1) / qb->obj_size;
	fprintf(log, "number of objects = %lu\n", qb->obj_count);
	qb->min_version = calloc(qb->storage_files, sizeof(uint64_t));
	assert(qb->min_version);
	qb->cur_version = calloc(qb->storage_files, sizeof(uint64_t));
	assert(qb->cur_version);
	qb->bitmap_sz = (qb->obj_count + 7) / 8;
	qb->bitmap = calloc(1, qb->bitmap_sz);
	assert(qb->bitmap);
	return 0;
}

static int qb_parse_json(FILE *log, struct qb_connection *qb, char *path) {
	int i, ret = 1;
	struct timespec tstart={}, tend={};
	json_value* value = NULL;

	int fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		fprintf(log, "fopen %s failed: %s\n", path, strerror(errno));
		goto out;
	}
	clock_gettime(CLOCK_MONOTONIC, &tstart);
	if (parse_json(fd)) {
	   fprintf(log, "cant json parse: %s\n", path);
	   goto out;
	}
	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(log, "parse_json took about %.5f seconds\n",
		   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
		   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	fflush(log);
	close(fd);
	assert(g_version == 2);
	assert(g_metadata);

	value = json_parse((json_char*) g_metadata, strlen(g_metadata));

	if (!value || value->type != json_object) {
		fprintf(log, "json metadata parse error\n");
		goto out;
	}

	for (i = 0; i < value->u.object.length; i++) {
		json_char *name = value->u.object.values[i].name;
		json_value *val = value->u.object.values[i].value;
		if (!strcmp(name, "quobyte_file_version")) {
			int j;
			vgotoout_if_n(val->type != json_array, "json parser error: quobyte_file_version has unexpected type (%d)", val->type);
			assert(val->u.array.length <= qb->storage_files);
			for (j = 0; j < val->u.array.length; j++) {
				json_value *entry = val->u.array.values[j];
				vdie_if_n(entry->type != json_integer, "json parser error: quobyte_file_version entry unexpected type (%d)", entry->type);
				assert(entry->u.integer >= 0);
				qb->min_version[j] = entry->u.integer;
			}
		} else if (!strcmp(name, "quobyte_file_id")) {
			vgotoout_if_n(val->type != json_string, "json parser error: quobyte_file_id has unexpected type (%d)", val->type);
			vgotoout_if_n(val->u.string.length != strlen(&qb->file_id[0]) || strncmp(&qb->file_id[0], val->u.string.ptr, strlen(&qb->file_id[0])), "quobyte_file_id in metadata does not match!", 0);
		}
	}

	assert(g_block_size == qb->obj_size);

	ret = 0;
out:
	return ret;
}

static int qb_get_changed_objects(FILE *log, struct qb_connection *qb) {
	int ret;
	struct timespec tstart={}, tend={};
	fprintf(log, "min version = ");
	dump_version(log, qb->min_version, qb->storage_files);
	fprintf(log, "\n");
	clock_gettime(CLOCK_MONOTONIC, &tstart);
	ret = quobyte_get_changed_objects(qb->fh, qb->min_version, qb->cur_version, qb->storage_files, qb->bitmap, qb->bitmap_sz);
	if (ret < 0) {
	fprintf(log, "quobyte_get_changed_objects: %s (%d)\n", strerror(errno), errno);
		return ret;
	}
	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(log, "quobyte_get_changed_objects took about %.5f seconds\n",
	   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
	   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	fflush(log);
	fprintf(log, "number of objects (ret) = %d\n", ret);
	assert (ret == qb->obj_count);
	fprintf(log, "cur version = ");
	dump_version(log, qb->cur_version, qb->storage_files);
	fprintf(log, "\n");
	return ret;
}

static int qb_close_file(FILE *log, struct qb_connection *qb) {
	struct timespec tstart={}, tend={};
	int ret;
	if (!qb->fh) return 0;
	clock_gettime(CLOCK_MONOTONIC, &tstart);
	ret = quobyte_close(qb->fh);
	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(log, "quobyte_close took about %.5f seconds\n",
	   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
	   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	fflush(log);
	qb->fh = NULL;
	free(qb->min_version);
	free(qb->cur_version);
	free(qb->bitmap);
	free(qb->path);
	return ret;
}
