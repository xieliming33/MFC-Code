#pragma once
//------------------------------------------------------------------------- VC6.0����ѡ��
#include "resource.h"		                                              // main symbols
//-------------------------------------------------------------------------VS2010����ѡ��
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
****                  ��Ϣ�򵯳�                                              ****
****                  MessageBox(_T("."),_T("��ܰ��ʾ"),MB_OK);               ****
****                  .cpp��ʹ�õ���Ϣ��������                                ****
****                  AfxMessageBox(L"��Ӧ�ó����Ѿ���������!");              ****
****                  ���þ�̬�ؼ�ֵ                                          ****
****                  GetDlgItem(IDC_COMMSTATE_STATIC)->SetWindowText(_T(""));****
****                  �߳��˳�����                                            ****
****                  CWinThread *handle=NULL;                                ****
****                  ::WaitForSingleObject(handle->m_hThread,1500);          ****
****                  ::TerminateThread(handle->m_hThread,0);                 ****
**** //IDC_RADIO1��IDC_RADIO2��Ĭ��ѡ��IDC_RADIO1                             ****
**** CheckRadioButton(IDC_RADIO1,IDC_RADIO2,IDC_RADIO1);                      ****
**** //���CTreeCtl�ؼ�InsertItem������ʹ��ʵ����                             ****
**** m_ComPortTreeListCtl.InsertItem(str,ParentItem,LastSiblingItem);         ****
**** m_ComPortTreeListCtl.InsertItem(_T("ģʽ:Com2"),NULL,NULL,ParentItem);   ****
**********************************************************************************
/*=================================================================================
1�������Ƿ�ȷ�Ͽ�
	if(IDNO==MessageBox(_T("�Ƿ�ɾ��ĩβ�Ĵ�վ?"),_T("��ܰ��ʾ"),
	MB_YESNO|MB_ICONINFORMATION))
		return ;
2��PreTranslateMessage������дʵ��
	if (pMsg->message == WM_KEYDOWN)  
	{  
		switch(pMsg->wParam)
		{  
		case VK_ESCAPE:           //Esc�����¼�  
			return true;  
		case VK_RETURN:           //Enter�����¼� 

			return true;
		case VK_F1:               //����������Ϣ
			return true;
		default:
		;
		}
	}
	return CDialogEx::PreTranslateMessage(pMsg);
3��Tree List Ctl
	SlaveListCtl.GetChildItem(TmpItem);
	SlaveListCtl.GetNextSiblingItem(t_child_item);
	SalveSubListCtl.SetItemText(nItem,_curStr);

4��//�������������еĴ���
	////////////////////////////////////////////////////////////////////////
	HANDLE dlgHandle = ::CreateMutex( NULL, FALSE, m_pszExeName);
	if( GetLastError() == ERROR_ALREADY_EXISTS )
	{
		CloseHandle( dlgHandle );
		AfxMessageBox(L"��Ӧ�ó����Ѿ���������!");
		dlgHandle= NULL;
		HWND hWndPrevious = ::GetWindow(::GetDesktopWindow(), GW_CHILD);
		while (::IsWindow(hWndPrevious))
		{
			// ��鴰���Ƿ���Ԥ��ı��
			// �У���������Ѱ�ҵ�����
			if (::GetProp(hWndPrevious, m_pszExeName))
			{
				// ����������С������ָ����С
				if (::IsIconic(hWndPrevious))
					::ShowWindow(hWndPrevious,SW_SHOWNORMAL);
				::ShowWindow(hWndPrevious, SW_RESTORE);
				// ����������
				::SetForegroundWindow(hWndPrevious);
				// �������ĶԻ��򼤻�
				::SetForegroundWindow(::GetLastActivePopup(hWndPrevious));
				// �˳���ʵ��
				return FALSE;
			}
			// ����Ѱ����һ������
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
	bool isfirst_flag;                                      //�����Ƿ��Ǹ�����
	CString cur_path;                                       //��ִ���ļ��ĵ�ǰ·��
	CMutex  *logmutex;                                      //��־�������
public:
	GeneralInterface();
	~GeneralInterface();
	//У��ӿ�
	WORD CalCheckSum(char* lpBuf,int iLen);                 //�����ۼӺ�
	BYTE modbus_lrc_calc(BYTE*buffer,WORD size);            //��������У��
	WORD CalCheckCRC(char* lpBuf,int iLen);                 //����CRCУ��ֵ
	//��ӡ��־�ӿ�
	void PrintLogFile(char * msg,int len);                  //���ַ���ӡ��־��Ϣ���ļ���
	void PrintLogFileByHex(char * msg,int len);             //��16���Ƶ���ʽ��ӡ��־�ļ�
	void PrintLogFileByBit(char * msg,int len,int pnum);    //�Զ����Ƶ���ʽ��ӡ��־�ļ�pnum ��ӡ���ٸ�������
	
	bool CStringToChar(CString pstr,char * ch,int len);     //CString ת�� char *
	CString CharBufToCString(char * buf,WORD buf_len);      //char*   ת��CString
	bool CStringToInt(CString str,int *res);                //CString ת�� int
	bool CStringToFloat(CString str,float *res);            //CString ת�� float

	CString  dwIP2csIP(DWORD dwIP);                         //DWORD��ipֵת��Ϊ0.0.0.0�ַ���
	char     ConvertHexChar(char ch);                       //�ַ�ת���ɶ�Ӧ��16����ֵ
	UINT     GetKeyCountByKeyStrNotStr(CString key_str,CString not_str,
		     CString file_path);                            //��ini�ļ��л�ȡ����key_str������not_str������
	wchar_t* Char2wChart(const char* utf);                  //�����ֽ�char*ת��Ϊ���ֽ�wchar_t* 
	char*    wChart2Char(const wchar_t* unicode);           //�����ֽ�wchar_t*ת��Ϊ���ֽ�char*
	CString  GetCurLocalTime();                             //��ȡ��ǰʱ��
	/*
	* ��������:
	*         CStringToHexCharbuf(CString src_str,char *des_buf,int des_buf_size,int * res_len)
	* ��������:
	*         CString ת����char* ��16������ʽ��eg _T("11 12"),{0x11,0x22},�ɹ�����0��ʧ�ܷ��ش�����
	* �����붨��:
	*         1 des_buf_size С�� src_str����
	*         2 Խ����
	*         3 ��������ݺ��зǷ��ַ�
	*         4 ������������16������
	*         5 �����ַ�
	*/
	int      CStringToHexCharbuf(CString src_str,char *des_buf,int des_buf_size,int * res_len);
	int      Bitap(const char *text, const char *find);     //�ַ���ƥ�����㷨
	void     TrimStr(CString &srcStr);                      //�ַ�������ð��(:)�ұ�
	void     TrimStrLeft(CString& srcStr);                  //�ַ�������ð��(:)���
	
	CString GetCurPath();                                   //��ȡ��ǰ·��
	CString GetModuleDir();                                 //��ȡ��ǰ��ִ���ļ���Ŀ¼
	//�����ļ�����Ի���
	CString SelectDirPath();
	CString SelectFilePath();

	//����INI�����ļ��Ľӿ�
	bool    IsExistConfFile(CString FilePath);                                  //�ж������ļ��治����textΪԭ�ַ�
	bool    DeleteDir(CString dir_path);                                        //ɾ��һ��Ŀ¼
	BOOL	IsExistDirectory(CString Path);										//�ж�Ŀ¼������
	BOOL	CreateDirectory(CString path);										//����Ŀ¼

	int     GetIntFromIniConf(CString Section,CString Key,int DefaultVal,CString FilePath);
	CString GetBufFromIniConf(CString Section,CString Key,CString DefaultStr,CString FilePath);
	void	WriteInifileToEmptyLine(CString pathstr);                           //��INI�ļ���д�����
	void	WriteInifileToInt(CString Section,CString Key,int Val,CString path);//��INI�ļ���д������ֵ
	void	WriteInifiletoCString(CString Section,CString Key,CString str,CString path);

	//�����е�λ��������0��1
	bool SetBitBuff(BYTE index,BYTE * buf,BYTE buf_len);
	bool ClrBitBuff(BYTE index,BYTE * buf,BYTE buf_len);
	void ClearBitBuff(BYTE * buf,BYTE buf_len);
	bool IsTrueBitBuff(BYTE index,BYTE * buf,BYTE buf_len);                     //�ж�ĳһλ�Ƿ�Ϊ1
	void ShowBitBuff(BYTE * buf,BYTE buf_len);
};

class MySocket
{
public:
	MySocket();
	~MySocket();
	/******���û�ȡ���Ա����*******/
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

	/******�����׽�������,�ɹ�����0��ʧ�ܷ��ش������*******/
	int SetSockAddrRuse();                         //��ַ����
	int SetSockNBlock();                           //������
	int SetSockBlock();                            //����ģʽ
	int SetSockRWBuff(int _buf);                   //�շ�����
	int SetSockRWTimeout(int _timeout);            //�շ���ʱ
	int SetSockBroadModel();                       //�㲥����

	/*******�׽��ְ󶨼���******/
	int BindListen();

	int  MySelect(SOCKET s,int iType,int iSec);
	bool ConnectSever(const char * s_ip,const int s_port);

	//�ر��׽���
	void CloseMySocket();
private:
	char bind_ip[48];
	int  bind_port;
	int  sock_fd;

	//��Ǳ���
	char sock_type;                                   //'t'--tcp,'u'--udp,'b'--broadcast
	bool block_flag;
};
