#ifndef CUSTOMUTILH
#define CUSTOMUTILH

typedef struct str_list	{
	int n;
	char **data;
	int *lengths;
}List;

typedef struct str_tokenizer	{
	int current;
	int n;
	char **tokens;
}Tokenizer;

char *ltrim(char *str, const char *seps);
char *rtrim(char *str, const char *seps);
char *trim(char *str, const char *seps);
int indexOf(char *s,const char **array,int length_array);

int hexchr2bin(char hex, char *out);
int hexs2bin(char *hex, unsigned char *out);
char *tohex(char *ptr,int length);

int hasMoreTokens(Tokenizer *t);
char *nextToken(Tokenizer *t);



#endif // CUSTOMUTILH
