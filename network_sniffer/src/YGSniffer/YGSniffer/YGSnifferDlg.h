
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
	// 在列表框中列出本机所有的显卡
	CComboBox m_comboAdapterList;

	// 在List列表框中，列出显卡的基本信息
	CListCtrl m_listAdapterInfo;

	// 在Tree结构树中，列出显卡的详细信息
	CTreeCtrl m_treeDetailInfo;

	// 在Edit文本编辑框中，显示出数据包的数据信息
	CEdit m_editDataInfo;

	// 实例化自定义类MyWinPcap的对象
	MyWinPcap tmpMyWinPcap;

	// Create thread handle
	HANDLE m_hdlThread; // Initial


public:
	afx_msg void OnBnClickedButtonStartsniffer();
	afx_msg void OnBnClickedFreshadapterlist();
	afx_msg void OnBnClickedStartsniffer();
	afx_msg void OnBnClickedStopsniffer();

	// 列出本机上的所有网卡
	void DispAllAdapters(void);

	// 返回在列表框中，被选中的网卡
	pcap_if_t* GetSelectedAdapter(int iSelectAdapterNo,int iTotalAdapter);

	// 显示选中的网卡数据包pkt信息到List Control列表框中
	void DispSelectedtoListCtrl(packet *pkt);

	// 获取正确的Mac地址
	void GetMacAddress(TCHAR * eth_dMac, u_char * eth_sMac);

	// 获取正确的Ethernet Type类型
	void GetMacType(CString &eth_strType, u_short eth_Type, bool isFirst);

	// 获取正确的IP Type类型
	void GetIPType(CString & ip_strIP, u_short ip_Type, bool isFirst);

	// 获取IP地址
	void GetIPAddress(TCHAR * ip_Address, ip_address *ip_addr);

	// 双击后把List Control列表中选中的详细信息，显示在Tree Control中
	afx_msg void OnNMDblclkAdapterinfo(NMHDR *pNMHDR, LRESULT *pResult);

	// 显示Mac（Ethernet）协议的详细信息
	void ShowMacDetail(HTREEITEM & tmphItem, const u_char * pkt_data);

	// 显示IP协议的详细信息
	void ShowIPDetail(HTREEITEM &hItem,const u_char *pkt_data);

	// 显示TCP协议的详细信息
	void ShowTCPDetail(HTREEITEM & hItem, const u_char * pkt_data);

	// 显示UDP协议的详细信息
	void GetUDPDetail(HTREEITEM & hItem, const u_char * pkt_data);

	// 显示ICMP协议的详细信息
	void GetICMPDetail(HTREEITEM & hItem, const u_char * pkt_data);
	
	// 显示Packet Data数据信息
	void GetDataInfo(CEdit & eText, packet *pkt);

	// 显示HTTP协议的详细信息
	void GetHTTPDetail(HTREEITEM & hItem, const u_char *pkt_data);

private:	
	// 记录接收到所有数据包的总数量
	u_int iStatistic_TotalProtocol;
	
	// 记录接收到IP协议包的总数量
	u_int iStatistic_TotalIP;

	// 记录接收到ARP协议包的总数量
	u_int iStatistic_TotalARP;

	// 记录接收到TCP协议包的总数量
	u_int iStatistic_TotalTCP;

	// 记录接收到UDP协议包的总数量
	u_int iStatistic_TotalUDP;

	// 记录接收到ICMP协议包的总数量
	u_int iStatistic_TotalICMP;

	// 记录接收到的HTTP协议包的总数量
	u_int iStatistic_TotalHTTP;

	// 记录接收到的FTP协议包的总数量
	u_int iStatistic_TotalFTP;

	// 记录接收到的SMTP协议包的总数量
	u_int iStatistic_TotalSMTP;

public:
	// 在“数据统计”组中，显示接收到的各种协议数据包统计信息
	void ShowStatisticInfo(void);

public:
	// 主对话框CYGSnifferDlg实例化为对象m_ygSnifferDlg
	CYGSnifferDlg *m_ygSnifferDlg;

private:
	// 浏览所有协议信息，此项设为开始默认值
	CButton * m_chkALL;

	// 仅浏览IP协议下的数据包信息
	CButton *m_chkIP;

	// 仅浏览ARP协议下的数据包信息
	CButton *m_chkARP;

	// 仅浏览TCP协议下的数据包信息
	CButton *m_chkTCP;

	// 仅浏览UDP协议下的数据包信息
	CButton *m_chkUDP;

	// 仅浏览ICMP协议下的数据包信息
	CButton *m_chkICMP;

public:
	// 设置过滤器，并在List Constrol列表框中显示出过滤出的信息
	void CheckedFiltertoListCtrl();

	// 选择了过滤协议后，立即执行过滤协议，并显示出过滤后的协议信息
	afx_msg void OnBnClickedImmdexec();

    // 选择了过滤协议后，又点击了取消选择，则全部清零
	afx_msg void OnBnClickedCancelsel();

	// 判断该协议是否为HTTP协议
	bool IsHTTP(const u_char *pkt_data);	
	afx_msg void OnBnClickedAbout();
};
