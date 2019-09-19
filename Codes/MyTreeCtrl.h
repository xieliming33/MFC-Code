#pragma once
//--------------------------------------------------------------------------------VC6.0
#include <afxtempl.h>
#include <afxwin.h>
//--------------------------------------------------------------------------------VS2010
//VS2010�����������������ͷ�ļ�

struct Color_Font
{
	COLORREF color;
	LOGFONT logfont;
};

// MyTreeCtrl

class MyTreeCtrl : public CTreeCtrl
{
	DECLARE_DYNAMIC(MyTreeCtrl)

public:
	MyTreeCtrl();
	virtual ~MyTreeCtrl();
	void SetItemColor(HTREEITEM hItem, COLORREF color);
protected:
	afx_msg void OnPaint();
protected:
	DECLARE_MESSAGE_MAP()

public:
	CMap<void*,void*,Color_Font,Color_Font&>m_mapColorFont;
};


