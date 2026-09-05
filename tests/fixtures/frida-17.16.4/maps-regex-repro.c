#include <glib.h>
#include <stdio.h>
int main(int argc, char **argv) {
  if(argc!=2)return 2;
  gchar *data;gsize size;GError *error=NULL;
  if(!g_file_get_contents(argv[1], &data, &size, &error))return 3;
  const char *pat="^([0-9a-f]+)-([0-9a-f]+) (\\S{4}) ([0-9a-f]+) ([0-9a-f]{2,}:[0-9a-f]{2,}) (\\d+) *([^\\n]*)$";
  for(int raw=0;raw<2;raw++) {
    GRegex *r=g_regex_new(pat,G_REGEX_MULTILINE|(raw?G_REGEX_RAW:0),0,&error);
    GMatchInfo *m=NULL;int count=0,libc=0;
    g_regex_match_full(r,data,size,0,0,&m,&error);
    while(g_match_info_matches(m)) {
      gchar *path=g_match_info_fetch(m,7);
      count++;if(g_str_has_suffix(path,"/libc.so"))libc++;g_free(path);
      if(!g_match_info_next(m,&error))break;
    }
    printf("raw=%d maps=%d libc=%d regex_error=%d\n",raw,count,libc,error!=NULL);
    g_clear_error(&error);g_match_info_free(m);g_regex_unref(r);
  }
  g_free(data);return 0;
}
