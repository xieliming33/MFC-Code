#pragma once
//------------------------------------------------------------------------- VC6.0编译选项
#include "resource.h"		                                              // main symbols
//-------------------------------------------------------------------------VS2010编译选项
//#include "afxwin.h"
//#define VS2010                                                          //Add 2019.1.26
//--------------------------------------------------------------------------------
#define MAXLOGSIZE 10*1024*1024
#define MAXLENGTH  2000*1024                                                      //--2M
/*********************************************************************************
****                  Author:xieliming                                        ****
****                  Update:2019.4.25                                        ****
****                  Version:   2.0.1                                        ****
****                  #include "Mfc.h"                                        ****
****                  Use Manual:extern GeneralInterface mfc_obj;             ****
****--------------------------------------------------------------------------****
****                  消息框弹出                                              ****
****                  MessageBox(_T("."),_T("温馨提示"),MB_OK);               ****
****                  .cpp中使用的消息弹出机制                                ****
****                  AfxMessageBox(L"该应用程序已经在运行中!");              ****
****                  设置静态控件值                                          ****
****                  GetDlgItem(IDC_COMMSTATE_STATIC)->SetWindowText(_T(""));****
****                  线程退出处理                                            ****
****                  CWinThread *handle=NULL;                                ****
****                  ::WaitForSingleObject(handle->m_hThread,1500);          ****
****                  ::TerminateThread(handle->m_hThread,0);                 ****
**** //IDC_RADIO1与IDC_RADIO2，默认选择IDC_RADIO1                             ****
**** CheckRadioButton(IDC_RADIO1,IDC_RADIO2,IDC_RADIO1);                      ****
**** //针对CTreeCtl控件InsertItem函数的使用实例：                             ****
**** m_ComPortTreeListCtl.InsertItem(str,ParentItem,LastSiblingItem);         ****
**** m_ComPortTreeListCtl.InsertItem(_T("模式:Com2"),NULL,NULL,ParentItem);   ****
**********************************************************************************
/*=================================================================================
1、弹出是否确认框
	if(IDNO==MessageBox(_T("是否删除末尾的从站?"),_T("温馨提示"),
	MB_YESNO|MB_ICONINFORMATION))
		return ;
2、PreTranslateMessage函数重写实现
	if (pMsg->message == WM_KEYDOWN)  
	{  
		switch(pMsg->wParam)
		{  
		case VK_ESCAPE:           //Esc按键事件  
			return true;  
		case VK_RETURN:           //Enter按键事件 

			return true;
		case VK_F1:               //开启帮助信息
			return true;
		default:
		;
		}
	}
	return CDialogEx::PreTranslateMessage(pMsg);
3、Tree List Ctl
	SlaveListCtl.GetChildItem(TmpItem);
	SlaveListCtl.GetNextSiblingItem(t_child_item);
	SalveSubListCtl.SetItemText(nItem,_curStr);

4、//检测程序正在运行的代码
	////////////////////////////////////////////////////////////////////////
	HANDLE dlgHandle = ::CreateMutex( NULL, FALSE, m_pszExeName);
	if( GetLastError() == ERROR_ALREADY_EXISTS )
	{
		CloseHandle( dlgHandle );
		AfxMessageBox(L"该应用程序已经在运行中!");
		dlgHandle= NULL;
		HWND hWndPrevious = ::GetWindow(::GetDesktopWindow(), GW_CHILD);
		while (::IsWindow(hWndPrevious))
		{
			// 检查窗口是否有预设的标记
			// 有，则是我们寻找的主窗
			if (::GetProp(hWndPrevious, m_pszExeName))
			{
				// 主窗口已最小化，则恢复其大小
				if (::IsIconic(hWndPrevious))
					::ShowWindow(hWndPrevious,SW_SHOWNORMAL);
				::ShowWindow(hWndPrevious, SW_RESTORE);
				// 将主窗激活
				::SetForegroundWindow(hWndPrevious);
				// 将主窗的对话框激活
				::SetForegroundWindow(::GetLastActivePopup(hWndPrevious));
				// 退出本实例
				return FALSE;
			}
			// 继续寻找下一个窗口
			hWndPrevious = ::GetWindow(hWndPrevious, GW_HWNDNEXT);
		}
		return FALSE;
	}
	////////////////////////////////////////////////////////////////////////
=================================================================================*/
#ifndef VS2010
class CMutex
{
public:
	CMutex();
	~CMutex();
	
	void Lock();
	void Unlock();
private:
	HANDLE m_mutex;
};
#endif

class GeneralInterface
{
private:
	bool isfirst_flag;                                      //程序是否是刚起来
	CString cur_path;                                       //可执行文件的当前路径
	CMutex  *logmutex;                                      //日志互斥变量
public:
	GeneralInterface();
	~GeneralInterface();
	//校验接口
	WORD CalCheckSum(char* lpBuf,int iLen);                 //计算累加和
	BYTE modbus_lrc_calc(BYTE*buffer,WORD size);            //计算纵向校验
	WORD CalCheckCRC(char* lpBuf,int iLen);                 //计算CRC校验值
	//打印日志接口
	void PrintLogFile(char * msg,int len);                  //以字符打印日志消息到文件中
	void PrintLogFileByHex(char * msg,int len);             //以16进制的形式打印日志文件
	void PrintLogFileByBit(char * msg,int len,int pnum);    //以二进制的形式打印日志文件pnum 打印多少个二进制
	
	bool CStringToChar(CString pstr,char * ch,int len);     //CString 转换 char *
	CString CharBufToCString(char * buf,WORD buf_len);      //char*   转换CString
	bool CStringToInt(CString str,int *res);                //CString 转换 int
	bool CStringToFloat(CString str,float *res);            //CString 转换 float

	CString  dwIP2csIP(DWORD dwIP);                         //DWORD的ip值转换为0.0.0.0字符串
	char     ConvertHexChar(char ch);                       //字符转换成对应的16进制值
	UINT     GetKeyCountByKeyStrNotStr(CString key_str,CString not_str,
		     CString file_path);                            //从ini文件中获取包含key_str不包含not_str的行数
	wchar_t* Char2wChart(const char* utf);                  //将单字节char*转化为宽字节wchar_t* 
	char*    wChart2Char(const wchar_t* unicode);           //将宽字节wchar_t*转化为单字节char*
	CString  GetCurLocalTime();                             //获取当前时间
	/*
	* 函数名称:
	*         CStringToHexCharbuf(CString src_str,char *des_buf,int des_buf_size,int * res_len)
	* 函数功能:
	*         CString 转换成char* 按16进制形式，eg _T("11 12"),{0x11,0x22},成功返回0，失败返回错误码
	* 错误码定义:
	*         1 des_buf_size 小于 src_str长度
	*         2 越界了
	*         3 输入的内容含有非法字符
	*         4 请输入完整的16进制数
	*         5 错误字符
	*/
	int      CStringToHexCharbuf(CString src_str,char *des_buf,int des_buf_size,int * res_len);
	int      Bitap(const char *text, const char *find);     //字符串匹配金典算法
	void     TrimStr(CString &srcStr);                      //字符串保留冒号(:)右边
	void     TrimStrLeft(CString& srcStr);                  //字符串保留冒号(:)左边
	
	CString GetCurPath();                                   //获取当前路径
	CString GetModuleDir();                                 //获取当前可执行文件的目录
	//弹出文件浏览对话框
	CString SelectDirPath();
	CString SelectFilePath();

	//处理INI配置文件的接口
	bool    IsExistConfFile(CString FilePath);                                  //判断配置文件存不存在text为原字符
	bool    DeleteDir(CString dir_path);                                        //删除一个目录
	BOOL	IsExistDirectory(CString Path);										//判断目录存在性
	BOOL	CreateDirectory(CString path);										//创建目录

	int     GetIntFromIniConf(CString Section,CString Key,int DefaultVal,CString FilePath);
	CString GetBufFromIniConf(CString Section,CString Key,CString DefaultStr,CString FilePath);
	void	WriteInifileToEmptyLine(CString pathstr);                           //向INI文件中写入空行
	void	WriteInifileToInt(CString Section,CString Key,int Val,CString path);//向INI文件中写入整形值
	void	WriteInifiletoCString(CString Section,CString Key,CString str,CString path);

	//缓存中的位操作，清0置1
	bool SetBitBuff(BYTE index,BYTE * buf,BYTE buf_len);
	bool ClrBitBuff(BYTE index,BYTE * buf,BYTE buf_len);
	void ClearBitBuff(BYTE * buf,BYTE buf_len);
	bool IsTrueBitBuff(BYTE index,BYTE * buf,BYTE buf_len);                     //判断某一位是否为1
	void ShowBitBuff(BYTE * buf,BYTE buf_len);
};

class MySocket
{
public:
	MySocket();
	~MySocket();
	/******设置获取类成员变量*******/
	bool SetBindIp(const char *_ip,const int _ipsize);
	char * GetBindIp()const;
	void SetBindPort(const int _port);
	int  GetBindPort()const;
	void SetBlockFlag(const bool _block_flag);
	bool GetBlockFlag()const;
	bool SetSockType(const char _sock_type);
	char GetSockType()const;
	bool CreateSockFd();
	int  GetSockFd()const;

	/******设置套接字属性,成功返回0，失败返回错误代码*******/
	int SetSockAddrRuse();                         //地址复用
	int SetSockNBlock();                           //非阻塞
	int SetSockBlock();                            //阻塞模式
	int SetSockRWBuff(int _buf);                   //收发缓存
	int SetSockRWTimeout(int _timeout);            //收发超时
	int SetSockBroadModel();                       //广播属性

	/*******套接字绑定监听******/
	int BindListen();

	int  MySelect(SOCKET s,int iType,int iSec);
	bool ConnectSever(const char * s_ip,const int s_port);

	//关闭套接字
	void CloseMySocket();
private:
	char bind_ip[48];
	int  bind_port;
	int  sock_fd;

	//标记变量
	char sock_type;                                   //'t'--tcp,'u'--udp,'b'--broadcast
	bool block_flag;
};
