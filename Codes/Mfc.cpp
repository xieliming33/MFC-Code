#include "stdafx.h"
#include "Mfc.h"

#ifndef VS2010
	#ifdef _DEBUG
	#define new DEBUG_NEW
	#undef THIS_FILE
	static char THIS_FILE[] = __FILE__;
	#endif
#endif

#ifndef VS2010  /*非vs2010模式下要自己封装互斥类*/
CMutex::CMutex()
{
	m_mutex = ::CreateMutex(NULL, FALSE, NULL);
}

CMutex::~CMutex()
{
	::CloseHandle(m_mutex);
}

void CMutex::Lock()
{
	DWORD d = WaitForSingleObject(m_mutex, INFINITE);
}

void CMutex::Unlock()
{
	::ReleaseMutex(m_mutex);
}
#endif

GeneralInterface mfc_obj;     //外部调用接口变变量

GeneralInterface::GeneralInterface()
{
	isfirst_flag=true;
#ifdef VS2010
	logmutex=new CMutex(NULL,false,NULL);
#else
	logmutex=new CMutex;
#endif
	cur_path=GetModuleDir();
}

GeneralInterface::~GeneralInterface()
{
	if(logmutex)
	{
		delete logmutex;
		logmutex=NULL;
	}
}

void GeneralInterface::WriteInifileToInt(CString Section,CString Key,int Val,CString path)
{
	CString str;
	str.Format(_T("%d"),Val);
#ifdef VS2010
	::WritePrivateProfileStringW(Section,Key,str,path);
#else
	::WritePrivateProfileString(Section,Key,str,path);
#endif
}

void GeneralInterface::WriteInifiletoCString(CString Section,CString Key,CString str,CString path)
{
#ifdef VS2010
	::WritePrivateProfileStringW(Section,Key,str,path);
#else
	::WritePrivateProfileString(Section,Key,str,path);
#endif
}

void  GeneralInterface::WriteInifileToEmptyLine(CString pathstr)
{
	CStdioFile f3( pathstr,CFile::modeWrite | CFile::typeText );
	TCHAR buf[] = _T("\n");
	f3.SeekToEnd();
	f3.WriteString(buf);                                        //第一行
	f3.Close();
}

CString GeneralInterface::GetCurPath()
{
	return this->cur_path;
}

bool GeneralInterface::CStringToChar(CString pstr,char * ch,int len)
{
#ifdef VS2010
	if(pstr.GetLength()>len)    return false;
	int strlen=pstr.GetLength();
	int nbyte=WideCharToMultiByte(CP_ACP,0,pstr,strlen,NULL,0,NULL,NULL);
	char * VoicePath=new char[nbyte+1];
	memset(VoicePath,0,nbyte+1);
	WideCharToMultiByte(CP_OEMCP,0,pstr,strlen,VoicePath,nbyte,NULL,NULL);
	VoicePath[nbyte]=0;
	memcpy(ch,VoicePath,nbyte+1);
	delete []VoicePath;
#else
	if(pstr.GetLength()>len)      return false;
	strncpy(ch,(LPCTSTR)pstr,pstr.GetLength());
#endif
	return true;
}

CString GeneralInterface::CharBufToCString(char * buf,WORD buf_len)
{
	CString str=_T("");
	if(NULL==buf) return           str;
#ifdef VS2010
	str.Format(_T("%s"),CStringW(buf));
#else
	str.Format(_T("%s"),CString(buf));
#endif
	return str;
}

bool  GeneralInterface::CStringToInt(CString str,int *res)                          //CString 转换 int
{
	char buf[1024]={0};
	if(this->CStringToChar(str,buf,sizeof(buf)))
	{
		*res = atoi(buf);
		return true;
	}
	else
		return false;
}

bool GeneralInterface::CStringToFloat(CString str,float * res)                      //CString 转换 float
{
	char buf[1024]={0};
	if(this->CStringToChar(str,buf,sizeof(buf)))
	{
		*res = atof(buf);
		return true;
	}
	else
		return false;
}

WORD GeneralInterface::CalCheckSum(char* lpBuf,int iLen)
{
	WORD wSum=0;
	int i=0;
	for(;i<iLen;++i)
		wSum+=*(BYTE*)(lpBuf+i);
	return wSum;
}

CString GeneralInterface::dwIP2csIP(DWORD dwIP)
{
	CString strIP = _T("");
	WORD add1,add2,add3,add4;
	add1=(WORD)(dwIP&255);
	add2=(WORD)((dwIP>>8)&255);
	add3=(WORD)((dwIP>>16)&255);
	add4=(WORD)((dwIP>>24)&255);
	strIP.Format(_T("%d.%d.%d"),add4,add3,add2);  
	return strIP;
}

BYTE GeneralInterface::modbus_lrc_calc(BYTE*buffer,WORD size)
{
	BYTE lrc=0U;
	for(WORD i=0U;i<size;++i)
		lrc+=*(buffer+i);
	lrc=(0xFFU-lrc)+1U;
	return lrc;
}

char GeneralInterface::ConvertHexChar(char ch)
{
	if((ch>='0')&&(ch<='9'))
		return ch-0x30;
	else if((ch>='A')&&(ch<='F'))
		return ch-'A'+10;
	else if((ch>='a')&&(ch<='f'))
		return ch-'a'+10;
	else
		return -1;
}

UINT  GeneralInterface::GetKeyCountByKeyStrNotStr(CString key_str,CString not_str,CString file_path)
{
	UINT cnt=0;
	char file_path_ch[128]={0};
	this->CStringToChar(file_path,file_path_ch,sizeof(file_path_ch));

	CString str=_T("");
	char data[1024]={0};
    FILE *fp=fopen(file_path_ch,"r");
	if(fp)
	{
		while(!feof(fp))
		{
			memset(data,0,sizeof(data));
			//fread(data,sizeof(data),1,fp);      //这个函数会全部读进来
			fgets(data, 1024, fp);                //这个函数可以按行读取
			UINT len=strlen(data);
			if(len>0)
			{
				while(len--)                     //从后往前遍历，遇到空格，回车，换行的都用
				{                                //'\0'覆盖掉
					if(*(data+len)=='\r'||*(data+len)=='\n'||*(data+len)==' ')
						*(data+len)='\0';
					else
						break;
				}
				len=strlen(data);
				if(len>0)
				{
#ifdef VS2010
					str.Format(_T("%s"),CStringW(data));
#else
					str.Format(_T("%s"),data);
					//AfxMessageBox(str);
#endif
					if(str.Find(key_str)!=-1&&str.Find(not_str)==-1)
					{
						cnt++;
					}
				}
			}
		}
		fclose(fp);
	}
	return cnt;
}

wchar_t* GeneralInterface::Char2wChart(const char* utf)                  //将单字节char*转化为宽字节wchar_t* 
{
	int nLen = MultiByteToWideChar( CP_ACP, MB_PRECOMPOSED, utf, -1, NULL, 0 );  
    if (nLen == 0)  
    {  
        return NULL;  
    }  
    wchar_t* pResult = new wchar_t[nLen];  
    MultiByteToWideChar( CP_ACP, MB_PRECOMPOSED, utf, -1, pResult, nLen );  
    return pResult;
}
char* GeneralInterface::wChart2Char(const wchar_t* unicode)              //将宽字节wchar_t*转化为单字节char*
{
	int nLen = WideCharToMultiByte( CP_ACP, 0, unicode, -1, NULL, 0, NULL, NULL );  
    if (nLen == 0)  
    {  
        return NULL;  
    }  
    char* pResult = new char[nLen];  
    WideCharToMultiByte( CP_ACP, 0, unicode, -1, pResult, nLen, NULL, NULL );  
    return pResult;
}
CString GeneralInterface::GetCurLocalTime()                              //获取当前时间
{
	SYSTEMTIME sm;
	CString local_time_str;
	memset(&sm,0,sizeof(SYSTEMTIME));
	GetLocalTime(&sm);
	local_time_str.Format(_T("%d-%d-%d %d:%d:%d"),sm.wYear,sm.wMonth,sm.wDay,sm.wHour,sm.wMinute,sm.wSecond);
	return local_time_str;
}

int GeneralInterface::CStringToHexCharbuf(CString src_str,char *des_buf,int des_buf_size,int * res_len)
{
	*res_len=0;
	if(src_str.GetLength()>des_buf_size) return 1;
	memset(des_buf,0,sizeof(des_buf_size));

	int  buf_size=src_str.GetLength()+10;
	char *buf=new char [buf_size];
	memset(buf,0,buf_size);
	this->CStringToChar(src_str,buf,buf_size);
	int hexdata=0,lowhexdata=0,hexdatalen=0;            //des_buf所含字符的byte个数
	///////////////////////////////////////////////////
	for(int i=0;i<src_str.GetLength();++i)
	{
		char chh=*(buf+i);
		if(chh==' ')
			continue;
		++i;
		if(i>=des_buf_size) return 2;
		char chl=*(buf+i);

		hexdata=this->ConvertHexChar(chh);
		if(hexdata<0)
			return 3;
		if(chl==' '||i>=src_str.GetLength())
			return 4;
		else
		{
			lowhexdata=this->ConvertHexChar(chl);
			if(lowhexdata<0)
				return 3;
			if((i+1)<src_str.GetLength()&&*(buf+i+1)!=' ')
				return 4;
		}

		if((hexdata==16)||(lowhexdata==16))
			return 5;
		else
			hexdata=hexdata*16+lowhexdata;

		++i;
		++*res_len;
		des_buf[hexdatalen++]=hexdata;
	}
	///////////////////////////////////////////////////
	if(NULL!=buf)
	{
		delete buf;
		buf=NULL;
	}
	return 0;
}

int  GeneralInterface::Bitap(const char *text, const char *find)            //字符串匹配金典算法
{
	if (text == '\0' || find == '\0')
		return -1;
	int text_len = strlen(text);
	int find_len = strlen(find);
	if (text_len < find_len)
		return -1;
	int i = 0;
	int j = find_len - 1;
	char *map=(char * )malloc(find_len + 1);              //
	map[0] = 1;
	for (i=1; i<=find_len; ++i)
		map[i] = 0;
	for (i=0; i< text_len; ++i)
	{
		for (j=find_len-1; j>=0; --j)
		{
			map[j+1] = map[j] & (text[i] == find[j]);
		}
		if (map[find_len] == 1)
		{
			return i - find_len + 1;
		}
	}
	free(map);
	return -1;
}

void GeneralInterface::TrimStr(CString &srcStr)                                                   //保留冒号右边
{
	char buf[128]={0};
	memset(buf,0,sizeof(buf));
	this->CStringToChar(srcStr,buf,sizeof(buf));
	int i=sizeof(buf)-1;
	while(*(buf+i)!=':'&&i>0)
	{
		--i;
	}
#ifdef VS2010
	srcStr.Format(_T("%s"),CStringW(buf+i+1));
#else
	srcStr.Format(_T("%s"),buf+i+1);
#endif
}

void GeneralInterface::TrimStrLeft(CString& srcStr)                                               //保留冒号左边
{
	char buf[128]={0};
	memset(buf,0,sizeof(buf));
	this->CStringToChar(srcStr,buf,sizeof(buf));
	int i=sizeof(buf)-1;
	while(*(buf+i)!=':'&&i>0)
	{
		*(buf+i)='\0';
		--i;
	}
#ifdef VS2010
	srcStr.Format(_T("%s"),CStringW(buf));
#else
	srcStr.Format(_T("%s"),buf);
#endif
}

CString GeneralInterface::SelectDirPath()
{
	//弹出目录选择框
	TCHAR pszPath[MAX_PATH];
	CString pathstr=_T("");
	BROWSEINFO bi;
	bi.hwndOwner=NULL;
	bi.pidlRoot=NULL;
	bi.pszDisplayName=NULL;
	bi.lpszTitle=TEXT("请选择保存目录");
	bi.ulFlags=BIF_RETURNONLYFSDIRS|BIF_STATUSTEXT;
	bi.lpfn=NULL;
	bi.lParam=0;
	bi.iImage=0;
	LPITEMIDLIST pid1=SHBrowseForFolder(&bi);
	if(pid1==NULL)
	{
		return _T("");
	}
	if(!SHGetPathFromIDList(pid1,pszPath)) return _T("");
	return pszPath;
}

CString GeneralInterface::SelectFilePath()
{
	CFileDialog dlg(TRUE, 0, 0, OFN_HIDEREADONLY, _T("文本文件|*.ini|所有文件|*.*||"),(CWnd::GetDesktopWindow()));
	if (dlg.DoModal())
	{
		CString filePath=dlg.GetPathName();                          //文件路径
		CString fileNameWithNoExt=dlg.GetFileTitle();                //文件名称
		return filePath;
	}
	return _T("");
}

void GeneralInterface::PrintLogFile(char * msg,int len)                      //打印日志消息到文件中
{
	CString log_path=_T("");
	log_path=cur_path+_T("\\Log.txt");
	char filepath[128]={0};
	CStringToChar(log_path,filepath,sizeof(filepath));
	if(isfirst_flag)
	{
		//程序刚起来日志文件存在把日志文件删除掉
		CFileFind finder;
		BOOL ifFind = finder.FindFile(log_path);
		if( ifFind )
		{
			CFile    TempFile;
			TempFile.Remove(log_path);
		}
		isfirst_flag=false;
	}
	CFileFind finder;
	BOOL ifFind = finder.FindFile(log_path);
	if( ifFind )
	{
		//超过一定大小5M把文件删除掉
		CFileStatus status;
		CFile::GetStatus(log_path,status);
		if(status.m_size>MAXLOGSIZE)
		{
			CFile    TempFile;
			TempFile.Remove(log_path);
		}
	}
	logmutex->Lock();
	FILE * file=fopen(filepath,"at+");
	if(!file)
	{
		logmutex->Unlock();
		fclose(file);
		file=NULL;
		return ;
	}
	fputs(msg,file);
	fclose(file);
	file=NULL;
	logmutex->Unlock();
}

void GeneralInterface::PrintLogFileByHex(char * msg,int len)                      //以16进制的形式打印日志文件
{
	CString log_path=_T("");
	log_path=cur_path+_T("\\Log.txt");
	char filepath[128]={0};
	CStringToChar(log_path,filepath,sizeof(filepath));
	if(isfirst_flag)
	{
		//程序刚起来日志文件存在把日志文件删除掉
		CFileFind finder;
		BOOL ifFind = finder.FindFile(log_path);
		if( ifFind )
		{
			CFile    TempFile;
			TempFile.Remove(log_path);
		}
		isfirst_flag=false;
	}
	CFileFind finder;
	BOOL ifFind = finder.FindFile(log_path);
	if( ifFind )
	{
		//超过一定大小5M把文件删除掉
		CFileStatus status;
		CFile::GetStatus(log_path,status);
		if(status.m_size>MAXLOGSIZE)
		{
			CFile    TempFile;
			TempFile.Remove(log_path);
		}
	}
	logmutex->Lock();
	FILE * file=fopen(filepath,"at+");
	if(!file){
		fclose(file);
		file=NULL;
		logmutex->Unlock();
		return ;
	}
	for(int i=0;i<len;++i)
	{
		if(i!=0&&i%23==0)
			fprintf(file,"\r\n");
		fprintf(file,"%02x ",*(BYTE*)(msg+i));
	}
	fprintf(file,"\r\n");
	fclose(file);
	file=NULL;
	logmutex->Unlock();
}

void GeneralInterface::PrintLogFileByBit(char * msg,int len,int pnum)             //以二进制的形式打印日志文件
{
	for(int i=0;i<pnum;++i)
	{
		if(IsTrueBitBuff(i,(BYTE*)msg,len))
			PrintLogFile("1 ",strlen("1 "));
		else
			PrintLogFile("0 ",strlen("0 "));
	}
	PrintLogFile("\r\n",strlen("\r\n"));
}

CString GeneralInterface::GetModuleDir()

{
	HMODULE module=GetModuleHandle(0);
	TCHAR pFileName[MAX_PATH];
	GetModuleFileName(module,pFileName,MAX_PATH);
	CString csFulPath(pFileName);
	int nPos=csFulPath.ReverseFind('\\');
	if(nPos<0)
		return CString(_T(""));
	else
		return csFulPath.Left(nPos);
}
namespace xlm
{
	unsigned int _crc16tab[256] =
	{
		0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
		0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
		0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
		0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
		0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
		0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
		0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
		0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
		0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
		0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
		0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
		0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
		0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
		0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
		0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
		0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
		0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
		0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
		0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
		0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
		0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
		0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
		0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
		0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
		0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
		0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
		0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
		0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
		0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
		0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
		0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
		0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
	};

	WORD _updcrc16(WORD crc,int c)
	{
		int tmp;
		tmp=crc^c;
		crc=(crc>>8)^_crc16tab[tmp & 0xff];
		return crc;
	}
}
WORD GeneralInterface::CalCheckCRC(char* lpBuf,int iLen)
{
	int i,ch;
	WORD wCRC=0xffff;
	for(i=0;i<iLen;++i)
	{
		ch=lpBuf[i];
		wCRC=xlm::_updcrc16(wCRC,ch);
	}
	return wCRC;
}

bool GeneralInterface::IsExistConfFile(CString FilePath)
{
#ifdef VS2010
	return PathFileExists(FilePath);
#else
	CFileFind fFind;
	return fFind.FindFile(FilePath);
#endif
}

bool GeneralInterface::DeleteDir(CString dir_path)                                        //删除一个目录
{
	CFileFind tempFind;
	CString src_dir_path=dir_path;
	dir_path+=_T("\\*.*");
	BOOL IsFinded = tempFind.FindFile(dir_path);
	while (IsFinded)
	{
		IsFinded = tempFind.FindNextFile();  
		DeleteFile(tempFind.GetFilePath());   
	}
	tempFind.Close();
	RemoveDirectory(src_dir_path);
	return true;
}

BOOL GeneralInterface::IsExistDirectory(CString Path)
{
	WIN32_FIND_DATA fd;
	BOOL ret = FALSE;
    HANDLE hFind = FindFirstFile(Path, &fd);
    if ((hFind != INVALID_HANDLE_VALUE) && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
		//目录存在
		ret = TRUE;
    }
    FindClose(hFind);
	return ret;
}

BOOL GeneralInterface::CreateDirectory(CString path)
{
#ifdef VS2010
	if(!::CreateDirectory(path,NULL))   
		return FALSE;   
	else
		return TRUE;
#else
	SECURITY_ATTRIBUTES attrib;
	attrib.bInheritHandle = FALSE;
	attrib.lpSecurityDescriptor = NULL;
	attrib.nLength = sizeof(SECURITY_ATTRIBUTES);
	
	return ::CreateDirectory( path, &attrib);
#endif
}

int  GeneralInterface::GetIntFromIniConf(CString Section,CString Key,int DefaultVal,CString FilePath)
{
	int val=::GetPrivateProfileInt(Section,Key,DefaultVal,FilePath);
	return val;
}

CString GeneralInterface::GetBufFromIniConf(CString Section,CString Key,CString DefaultStr,CString FilePath)
{
	CString res_str=_T("");
	::GetPrivateProfileString(Section,Key,DefaultStr,res_str.GetBuffer(MAX_PATH),MAX_PATH,FilePath);
	res_str.ReleaseBuffer();
	return res_str;
}

bool GeneralInterface::SetBitBuff(BYTE index,BYTE * buf,BYTE buf_len)
{
	int i=0,j=0;
	i=index/8;
	j=index%8;
	if(i<buf_len)
	{
		(*(buf+i))|=(1<<j);
		return true;
	}
	else
		return false;
}

bool GeneralInterface::ClrBitBuff(BYTE index,BYTE * buf,BYTE buf_len)
{
	int i=0,j=0;
	i=index/8;
	j=index%8;
	if(i<buf_len)
	{
		(*(buf+i))&=~(1<<j);
		return true;
	}
	else
		return false;
}

void GeneralInterface::ClearBitBuff(BYTE * buf,BYTE buf_len)
{
	memset((char*)buf,0,buf_len);
}

bool GeneralInterface::IsTrueBitBuff(BYTE index,BYTE * buf,BYTE buf_len)                                    //鍒ゆ柇鏄惁涓?
{
	int i=0,j=0;
	i=index/8;
	j=index%8;
	if(*(buf+i)&(1<<j))
		return true;
	else
		return false;
}
void GeneralInterface::ShowBitBuff(BYTE * buf,BYTE buf_len)
{
	for(int i=0;i<buf_len;++i)
	{
		if(i!=0&&i%8==0)
			printf("\n");
		else if(i!=0)
			printf(" ");
		for(int j=0;j<8;++j)
		{
			if(*(buf+i)&(1<<j))
				printf("1");
			else
				printf("0");
		}
	}
	printf("\n");
}
////////////////////////////////////////////////////////////////////////////////
/*                          网络实现代码                                      */
////////////////////////////////////////////////////////////////////////////////
MySocket::MySocket()
{
	memset(this->bind_ip,0,sizeof(this->bind_ip));
	memcpy(this->bind_ip,"127.0.0.1",sizeof("127.0.0.1"));
	bind_port=999;
	block_flag=false;                                                        //默认非阻塞模式
	this->sock_type='t';                                                     //默认为TCP模式
	this->sock_fd=-1;
}

MySocket::~MySocket()
{
	if(-1!=sock_fd)
	{
		::closesocket(this->sock_fd);
		this->sock_fd=-1;
	}
}
//绑定ip
bool MySocket::SetBindIp(const char *_ip,const int _ipsize)
{
	if(_ipsize>48) return false;
	memcpy(this->bind_ip,_ip,_ipsize);
	return true;
}

char * MySocket::GetBindIp()const
{
	return (char*)this->bind_ip;
}
//绑定端口
void MySocket::SetBindPort(const int _port)
{
	this->bind_port=_port;
}
int  MySocket::GetBindPort()const
{
	return this->bind_port;
}
//阻塞标记
void MySocket::SetBlockFlag(const bool _block_flag)
{
	this->block_flag=_block_flag;
}

bool MySocket::GetBlockFlag()const
{
	return this->block_flag;
}

//类型标记
bool MySocket::SetSockType(const char _sock_type)
{
	switch(_sock_type)
	{
	case 't':
	case 'u':
	case 'b':
		this->sock_type=_sock_type;
		break;
	default:
		return false;
	}
	return true;
}

char MySocket::GetSockType()const
{
	return this->sock_type;
}
//套接字描述符
bool MySocket::CreateSockFd()
{
	if(this->sock_fd!=-1)
	{
		::closesocket(this->sock_fd);
		this->sock_fd=-1;
	}
	do
	{
		if('t'==this->sock_type)
		{
			this->sock_fd=socket(AF_INET,SOCK_STREAM,0);
			if(-1==this->sock_fd) break;
		}
		else if('u'==this->sock_type)
		{
			this->sock_fd=socket(AF_INET,SOCK_DGRAM,0);
			if(-1==this->sock_fd) break;
		}
		else if('b'==this->sock_type)
		{
			this->sock_fd=socket(AF_INET,SOCK_DGRAM,0);
			if(-1==this->sock_fd) break;
		}
		else
			break;
		return true;
	}while(0);
	this->CloseMySocket();
	return false;
}
int  MySocket::GetSockFd()const
{
	return this->sock_fd;
}
//套接字设置地址复用
int MySocket::SetSockAddrRuse()
{
	int err_code=0;
	BOOL opt_reuse = TRUE;
	if(setsockopt(this->sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt_reuse, sizeof(opt_reuse))!=0)
	{
		this->CloseMySocket();
		err_code=::GetLastError();
	}
	return err_code;
}
//套接字绑定监听
int MySocket::BindListen()
{
	int err_code=0;
	struct sockaddr_in bind_addr;
	memset(&bind_addr,0,sizeof(struct sockaddr_in));
	bind_addr.sin_family=AF_INET;
	bind_addr.sin_addr.S_un.S_addr=inet_addr(this->bind_ip);
	bind_addr.sin_port=htons(this->bind_port);

	do
	{
		if(bind(this->sock_fd,(struct sockaddr*)&bind_addr,sizeof(struct sockaddr))==-1)
		{
			err_code=::GetLastError();
			break;
		}
		if(listen(this->sock_fd,100)==-1)
		{
			err_code=::GetLastError();
			break;
		}
		return err_code;
	}while(0);
	this->CloseMySocket();
	return err_code;
}
//设置套接字非阻塞与阻塞模式
int MySocket::SetSockNBlock()
{
	int err_code=0;
	unsigned long nEnNoBlocking=1;
	if(ioctlsocket(this->sock_fd,FIONBIO,&nEnNoBlocking)!=0 )
	{
		this->CloseMySocket();
		err_code=::GetLastError();
	}
	return err_code;
}
int MySocket::SetSockBlock()
{
	int err_code=0;
	unsigned long nEnNoBlocking=0;
	if(ioctlsocket(this->sock_fd,FIONBIO,&nEnNoBlocking)!=0 )
	{
		this->CloseMySocket();
		err_code=::GetLastError();
	}
	return err_code;
}
//设置套接字收发缓存
int MySocket::SetSockRWBuff(int _buf)
{
	int err_code=0;
	do
	{
		if(setsockopt(this->sock_fd,SOL_SOCKET,SO_RCVBUF,(char*)&_buf,sizeof(int))!=0)
		{
			err_code=::GetLastError();
			break;
		}
		if(setsockopt(this->sock_fd,SOL_SOCKET,SO_SNDBUF,(char*)&_buf,sizeof(int))!=0)
		{
			err_code=::GetLastError();
			break;
		}
		return err_code;
	}while(0);
	this->CloseMySocket();
	return err_code;
}
int MySocket::SetSockRWTimeout(int _timeout)
{
	int err_code=0;
	struct timeval tv;
	memset(&tv,0,sizeof(struct timeval));
	tv.tv_sec=_timeout;
	tv.tv_usec=0;

	do
	{
		if(setsockopt(this->sock_fd,SOL_SOCKET,SO_RCVTIMEO,(char*)&tv,sizeof(struct timeval))!=0)
		{
			err_code=::GetLastError();
			break;
		}
		if(setsockopt(this->sock_fd,SOL_SOCKET,SO_SNDTIMEO,(char*)&tv,sizeof(struct timeval))!=0)
		{
			err_code=::GetLastError();
			break;
		}
		return err_code;
	}while(0);
	this->CloseMySocket();
	return err_code;
}

int MySocket::SetSockBroadModel()
{
	int err_code=0;
	const int opt=1;
	if(setsockopt(this->sock_fd,SOL_SOCKET,SO_BROADCAST,(char*)&opt,sizeof(opt))!=0)
	{
		this->CloseMySocket();
		err_code=::GetLastError();
	}
	return err_code;
}

//连接服务器
int  MySocket::MySelect(SOCKET s,int iType,int iSec)
{
	fd_set fds;
	fds.fd_count = 1;
	fds.fd_array[0] = s;
	struct timeval Timeout;
	Timeout.tv_sec = iSec;                     //time out seconds
	Timeout.tv_usec = 0;
	if( iType==0 )	return select(1, &fds, NULL, NULL, &Timeout);
	if( iType==1 )	return select(1, NULL, &fds, NULL, &Timeout);
	return select(1, NULL, NULL, &fds, &Timeout);
}

bool MySocket::ConnectSever(const char * s_ip,const int s_port)
{
	unsigned long nEnNoBlocking=1;
	if(this->GetBlockFlag())
	{
		if( ioctlsocket(this->sock_fd,FIONBIO,&nEnNoBlocking)!=0 )
		{
			this->CloseMySocket();
			return false;
		}
	}
	struct sockaddr_in saddr;
	memset(&saddr,0,sizeof(struct sockaddr_in));
	saddr.sin_family=AF_INET;
	saddr.sin_port=htons(s_port);
	saddr.sin_addr.S_un.S_addr=inet_addr(s_ip);

	connect(this->sock_fd,(struct sockaddr*)&saddr,sizeof(struct sockaddr));
	//检查是否可写入
	if( MySelect(this->sock_fd,1,4)<=0 )
	{
		this->CloseMySocket();
		return false;
	}
	//Set sock blocking mode
	if(this->GetBlockFlag())
	{
		nEnNoBlocking=0;
		if( ioctlsocket(this->sock_fd,FIONBIO,&nEnNoBlocking)!=0 )
		{
			this->CloseMySocket();
			return false;
		}
	}
	return true;
}
//关闭套接字
void MySocket::CloseMySocket()
{
	if(-1!=sock_fd)
	{
		::closesocket(this->sock_fd);
		this->sock_fd=-1;
	}
}