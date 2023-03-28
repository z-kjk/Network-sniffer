
// YGSnifferDlg.h : header file
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"

#include "MyWinPcap.h"

// CYGSnifferDlg dialog
class CYGSnifferDlg : public CDialog
{
// Construction
public:
	CYGSnifferDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_YGSNIFFER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();

	afx_msg LRESULT Message_WinPcap(WPARAM wParam,LPARAM lParam); //===== ** create thread's function ** ======
	DECLARE_MESSAGE_MAP()

// ================== ** create self var and function ** =================
private:
	// ���б�����г��������е��Կ�
	CComboBox m_comboAdapterList;

	// ��List�б���У��г��Կ��Ļ�����Ϣ
	CListCtrl m_listAdapterInfo;

	// ��Tree�ṹ���У��г��Կ�����ϸ��Ϣ
	CTreeCtrl m_treeDetailInfo;

	// ��Edit�ı��༭���У���ʾ�����ݰ���������Ϣ
	CEdit m_editDataInfo;

	// ʵ�����Զ�����MyWinPcap�Ķ���
	MyWinPcap tmpMyWinPcap;

	// Create thread handle
	HANDLE m_hdlThread; // Initial


public:
	afx_msg void OnBnClickedButtonStartsniffer();
	afx_msg void OnBnClickedFreshadapterlist();
	afx_msg void OnBnClickedStartsniffer();
	afx_msg void OnBnClickedStopsniffer();

	// �г������ϵ���������
	void DispAllAdapters(void);

	// �������б���У���ѡ�е�����
	pcap_if_t* GetSelectedAdapter(int iSelectAdapterNo,int iTotalAdapter);

	// ��ʾѡ�е��������ݰ�pkt��Ϣ��List Control�б����
	void DispSelectedtoListCtrl(packet *pkt);

	// ��ȡ��ȷ��Mac��ַ
	void GetMacAddress(TCHAR * eth_dMac, u_char * eth_sMac);

	// ��ȡ��ȷ��Ethernet Type����
	void GetMacType(CString &eth_strType, u_short eth_Type, bool isFirst);

	// ��ȡ��ȷ��IP Type����
	void GetIPType(CString & ip_strIP, u_short ip_Type, bool isFirst);

	// ��ȡIP��ַ
	void GetIPAddress(TCHAR * ip_Address, ip_address *ip_addr);

	// ˫�����List Control�б���ѡ�е���ϸ��Ϣ����ʾ��Tree Control��
	afx_msg void OnNMDblclkAdapterinfo(NMHDR *pNMHDR, LRESULT *pResult);

	// ��ʾMac��Ethernet��Э�����ϸ��Ϣ
	void ShowMacDetail(HTREEITEM & tmphItem, const u_char * pkt_data);

	// ��ʾIPЭ�����ϸ��Ϣ
	void ShowIPDetail(HTREEITEM &hItem,const u_char *pkt_data);

	// ��ʾTCPЭ�����ϸ��Ϣ
	void ShowTCPDetail(HTREEITEM & hItem, const u_char * pkt_data);

	// ��ʾUDPЭ�����ϸ��Ϣ
	void GetUDPDetail(HTREEITEM & hItem, const u_char * pkt_data);

	// ��ʾICMPЭ�����ϸ��Ϣ
	void GetICMPDetail(HTREEITEM & hItem, const u_char * pkt_data);
	
	// ��ʾPacket Data������Ϣ
	void GetDataInfo(CEdit & eText, packet *pkt);

	// ��ʾHTTPЭ�����ϸ��Ϣ
	void GetHTTPDetail(HTREEITEM & hItem, const u_char *pkt_data);

private:	
	// ��¼���յ��������ݰ���������
	u_int iStatistic_TotalProtocol;
	
	// ��¼���յ�IPЭ�����������
	u_int iStatistic_TotalIP;

	// ��¼���յ�ARPЭ�����������
	u_int iStatistic_TotalARP;

	// ��¼���յ�TCPЭ�����������
	u_int iStatistic_TotalTCP;

	// ��¼���յ�UDPЭ�����������
	u_int iStatistic_TotalUDP;

	// ��¼���յ�ICMPЭ�����������
	u_int iStatistic_TotalICMP;

	// ��¼���յ���HTTPЭ�����������
	u_int iStatistic_TotalHTTP;

	// ��¼���յ���FTPЭ�����������
	u_int iStatistic_TotalFTP;

	// ��¼���յ���SMTPЭ�����������
	u_int iStatistic_TotalSMTP;

public:
	// �ڡ�����ͳ�ơ����У���ʾ���յ��ĸ���Э�����ݰ�ͳ����Ϣ
	void ShowStatisticInfo(void);

public:
	// ���Ի���CYGSnifferDlgʵ����Ϊ����m_ygSnifferDlg
	CYGSnifferDlg *m_ygSnifferDlg;

private:
	// �������Э����Ϣ��������Ϊ��ʼĬ��ֵ
	CButton * m_chkALL;

	// �����IPЭ���µ����ݰ���Ϣ
	CButton *m_chkIP;

	// �����ARPЭ���µ����ݰ���Ϣ
	CButton *m_chkARP;

	// �����TCPЭ���µ����ݰ���Ϣ
	CButton *m_chkTCP;

	// �����UDPЭ���µ����ݰ���Ϣ
	CButton *m_chkUDP;

	// �����ICMPЭ���µ����ݰ���Ϣ
	CButton *m_chkICMP;

public:
	// ���ù�����������List Constrol�б������ʾ�����˳�����Ϣ
	void CheckedFiltertoListCtrl();

	// ѡ���˹���Э�������ִ�й���Э�飬����ʾ�����˺��Э����Ϣ
	afx_msg void OnBnClickedImmdexec();

    // ѡ���˹���Э����ֵ����ȡ��ѡ����ȫ������
	afx_msg void OnBnClickedCancelsel();

	// �жϸ�Э���Ƿ�ΪHTTPЭ��
	bool IsHTTP(const u_char *pkt_data);	
	afx_msg void OnBnClickedAbout();
};
