#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
#include <io.h>
#include <string>
#include <string.h>

#include <vector>

using namespace std;

vector<string> get_files_from_dir(char * dir,char *filter=NULL)
{
	vector<string> rst;
	_finddata_t file;
	long lf = _findfirst(dir, &file);
	if (lf == -1)
	{
		printf("error (%s,%d):canot read directory:%s\n", __FUNCTION__, __LINE__, dir);
	}
	else
	{
		while (_findnext(lf, &file) == 0)
		{
			if (strcmp(file.name, ".") == 0 || strcmp(file.name, "..") == 0)
				// filter .. and . directory.
			{
				continue;
			}
			if (filter == NULL || strstr(file.name, filter) != NULL)
			{
				rst.push_back(file.name);
			}
		}
	}
	return rst;
}