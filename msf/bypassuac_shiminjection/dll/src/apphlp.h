// apphelp.h
#include "windows.h"

#define TAG_TYPE_LIST 28679  

typedef enum _PATH_TYPE {   
	DOS_PATH,  
	NT_PATH  
} PATH_TYPE;  

typedef HANDLE PDB;  
typedef DWORD TAG;  
typedef DWORD INDEXID;  
typedef DWORD TAGID;  

typedef struct tagATTRINFO {  
	TAG  tAttrID;  
	DWORD dwFlags;  
	union {  
		ULONGLONG ullAttr;  
		DWORD   dwAttr;  
		TCHAR   *lpAttr;  
	};  
} ATTRINFO, *PATTRINFO;  

typedef PDB (WINAPI *SdbCreateDatabasePtr)(LPCWSTR, PATH_TYPE);  
typedef VOID (WINAPI *SdbCloseDatabasePtr)(PDB);  
typedef VOID (WINAPI *SdbCloseDatabaseWritePtr)(PDB);  
typedef BOOL (WINAPI *SdbDeclareIndexPtr)(PDB, TAG, TAG, DWORD, BOOL, INDEXID *);  
typedef BOOL (WINAPI *SdbCommitIndexesPtr)(PDB);  
typedef TAGID (WINAPI *SdbBeginWriteListTagPtr)(PDB, TAG);  
typedef BOOL (WINAPI *SdbEndWriteListTagPtr)(PDB, TAGID);  
typedef BOOL (WINAPI *SdbWriteQWORDTagPtr)(PDB, TAG, ULONGLONG);  
typedef BOOL (WINAPI *SdbWriteStringTagPtr)(PDB, TAG, LPCWSTR);  
typedef BOOL (WINAPI *SdbWriteDWORDTagPtr)(PDB, TAG, DWORD);  
typedef BOOL (WINAPI *SdbWriteBinaryTagPtr)(PDB, TAG, PBYTE, DWORD);  
typedef BOOL (WINAPI *SdbStartIndexingPtr)(PDB, INDEXID);  
typedef BOOL (WINAPI *SdbStopIndexingPtr)(PDB, INDEXID);  

typedef struct _APPHELP_API {  
	SdbCreateDatabasePtr         SdbCreateDatabase;  
	SdbCloseDatabasePtr          SdbCloseDatabase;  
	SdbCloseDatabaseWritePtr     SdbCloseDatabaseWrite;  
	SdbDeclareIndexPtr           SdbDeclareIndex;  
	SdbCommitIndexesPtr          SdbCommitIndexes;  
	SdbBeginWriteListTagPtr      SdbBeginWriteListTag;  
	SdbEndWriteListTagPtr        SdbEndWriteListTag;  
	SdbWriteQWORDTagPtr          SdbWriteQWORDTag;  
	SdbWriteStringTagPtr         SdbWriteStringTag;  
	SdbWriteDWORDTagPtr          SdbWriteDWORDTag;  
	SdbWriteBinaryTagPtr         SdbWriteBinaryTag;  
	SdbStartIndexingPtr          SdbStartIndexing;  
	SdbStopIndexingPtr           SdbStopIndexing;  
} APPHELP_API, *PAPPHELP_API;  