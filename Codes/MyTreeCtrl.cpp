// MyTreeCtrl.cpp : implementation file
//

#include "stdafx.h"
#include "MyTreeCtrl.h"


// MyTreeCtrl
//ʹ��CMap���������item��Ӧ�����塢��ɫ��Ϣ

IMPLEMENT_DYNAMIC(MyTreeCtrl, CTreeCtrl)

	MyTreeCtrl::MyTreeCtrl()
{

}

MyTreeCtrl::~MyTreeCtrl()
{
}


BEGIN_MESSAGE_MAP(MyTreeCtrl, CTreeCtrl)
	ON_WM_PAINT() 
END_MESSAGE_MAP()



// MyTreeCtrl message handlers

void MyTreeCtrl::SetItemColor(HTREEITEM hItem, COLORREF color)
{
	Color_Font cf;  
    if( !m_mapColorFont.Lookup( hItem, cf ) )  
        cf.logfont.lfFaceName[0] = '\0';  
    cf.color = color;  
    m_mapColorFont[hItem] = cf;  
}

afx_msg void MyTreeCtrl::OnPaint()
{
	//��ȡ��ǰ���ƶ����DC  
	CPaintDC dc(this);  
	// ʹ�ý�Ҫ���ƵĶ����DC����һ��memory DC  
	//memory device context�ĸ�������ڴ��д���һ���ṹ����ӳһ����ʾ����Ļ���򡢴��ڡ�  
	//��ӡ���ȣ��ı��档�������������ڴ���׼����Ҫ��ʾ��ͼ�񣬴Ӷ�ʵ��˫���棬���ˢ��  
	//�ٶȼ���ˢ��ʱ��������˸��  
	CDC memDC;  
	//�ӵ�ǰDC�����ڴ����  
	memDC.CreateCompatibleDC( &dc );  

	//����CRect��������ȷ������  
	CRect rcClip, rcClient;  
	//��ȡ��ǰ����ı߽�����  
	dc.GetClipBox( &rcClip );  
	//��ȡ��ǰ������û�����  
	GetClientRect(&rcClient);  

	// Select a compatible bitmap into the memory DC  
	//����һ��bmp�ļ�����ΪmemDC������  
	//���ļ��Ĵ�С������������ͬ  
	CBitmap bitmap;  
	bitmap.CreateCompatibleBitmap( &dc, rcClient.Width(), rcClient.Height() );  
	memDC.SelectObject( &bitmap );  

	// Set clip region to be same as that in paint DC  
	//ͨ������ı߽����򴴽�CRgn����  
	CRgn rgn;  
	rgn.CreateRectRgnIndirect( &rcClip );  
	memDC.SelectClipRgn(&rgn);  
	rgn.DeleteObject();  


	// First let the control do its default drawing.  
	//�����ÿؼ��Լ�����Ĭ�ϵĻ��ƣ����Ƶ��ڴ���  
	CWnd::DefWindowProc( WM_PAINT, (WPARAM)memDC.m_hDC, 0 );  

	//��ȡ��״�ؼ��ĵ�һ���ڵ�  
	HTREEITEM hItem = GetFirstVisibleItem();  

	//���������  
	int n = GetVisibleCount()+1;  
	while( hItem && n--)  
	{  
		CRect rect;  

		// Do not meddle with selected items or drop highlighted items  
		//����ѡ�еĽڵ��ʵ���ϷŹ��ܵĽڵ���в���  
		UINT selflag = TVIS_DROPHILITED | TVIS_SELECTED;  

		//�������塢��ɫ  
		Color_Font cf;  


		//��������  
		if ( !(GetItemState( hItem, selflag ) & selflag )  
			&& m_mapColorFont.Lookup( hItem, cf ))  
		{  
			CFont *pFontDC;  
			CFont fontDC;  
			LOGFONT logfont;  

			if( cf.logfont.lfFaceName[0] != '\0' )  
			{  
				//�û�����������  
				logfont = cf.logfont;  
			}  
			else  
			{  
				// �û�û�ж��壬ʹ��ϵͳ����  
				CFont *pFont = GetFont();  
				pFont->GetLogFont( &logfont );  
			}  

			//�û��Ƿ��趨�ڵ�Ϊ�Ӵ�  

			//��������  
			fontDC.CreateFontIndirect( &logfont );  
			pFontDC = memDC.SelectObject( &fontDC );  

			//����������ɫ  
			if( cf.color != (COLORREF)-1 )  
				memDC.SetTextColor( cf.color );  

			//��ȡ�ڵ�����  
			CString sItem = GetItemText( hItem );  

			//��ȡ�ڵ�����  
			GetItemRect( hItem, &rect, TRUE );  
			//���ñ���ɫΪϵͳɫ  
			memDC.SetBkColor( GetSysColor( COLOR_WINDOW ) );  
			memDC.SetBkMode(TRANSPARENT);  
			//���ڴ��е�ͼƬд������,Ϊ�ýڵ������  
			memDC.TextOut( rect.left+2, rect.top+1, sItem );  

			memDC.SelectObject( pFontDC );  
		}  
		hItem = GetNextVisibleItem( hItem );  
	}  


	dc.BitBlt( rcClip.left, rcClip.top, rcClip.Width(), rcClip.Height(), &memDC,  
		rcClip.left, rcClip.top, SRCCOPY );  

}