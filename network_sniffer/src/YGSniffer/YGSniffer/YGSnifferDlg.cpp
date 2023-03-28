
// YGSnifferDlg.cpp : implementation file
//

#include "stdafx.h"
#include "YGSniffer.h"
#include "YGSnifferDlg.h"

#include <vector>
using namespace std;

#include <atlconv.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//===== ** create message's var ** =====
#define M_MESSAGEWINPCAP (WM_USER+50)
static HWND hDlgHandle;
char *packet_filter;//===============================================================================

//=== ** create thread's function ** ===
DWORD WINAPI Thread_GetFilterData(LPVOID);
DWORD dwThread;
//== ** create WinPcap's function ** ===
/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
private:

};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{

}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CYGSnifferDlg dialog
// 构造函数，将统计数据初始化为0；



CYGSnifferDlg::CYGSnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CYGSnifferDlg::IDD, pParent),m_hdlThread(NULL)
	, iStatistic_TotalIP(0)
	, iStatistic_TotalProtocol(0)
	, iStatistic_TotalARP(0)
	, iStatistic_TotalTCP(0)
	, iStatistic_TotalUDP(0)
	, iStatistic_TotalICMP(0)
	, iStatistic_TotalHTTP(0)
	, iStatistic_TotalFTP(0)
	, iStatistic_TotalSMTP(0)
	, m_chkALL(NULL)
	, m_chkIP(NULL)
	, m_chkARP(NULL)
	, m_chkTCP(NULL)
	, m_chkUDP(NULL)
	, m_chkICMP(NULL)
	, m_ygSnifferDlg(NULL)
	

{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CYGSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, TREE_DETAILINFO, m_treeDetailInfo);
	DDX_Control(pDX, COMBO_ADAPTERLIST, m_comboAdapterList);
	DDX_Control(pDX, LIST_ADAPTERINFO, m_listAdapterInfo);
	DDX_Control(pDX, EDIT_DATAINFO, m_editDataInfo);
}

BEGIN_MESSAGE_MAP(CYGSnifferDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()

	ON_MESSAGE(M_MESSAGEWINPCAP,Message_WinPcap) //===== ** Mapping Message ** ======  //CYGSnifferDlg::Message_WinPcap
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(BUTTON_FRESHADAPTERLIST, &CYGSnifferDlg::OnBnClickedFreshadapterlist)
	ON_BN_CLICKED(BUTTON_STARTSNIFFER, &CYGSnifferDlg::OnBnClickedStartsniffer)
	ON_BN_CLICKED(BUTTON_STOPSNIFFER, &CYGSnifferDlg::OnBnClickedStopsniffer)
	ON_NOTIFY(NM_DBLCLK, LIST_ADAPTERINFO, &CYGSnifferDlg::OnNMDblclkAdapterinfo)
	ON_BN_CLICKED(BUTTON_IMMDEXEC, &CYGSnifferDlg::OnBnClickedImmdexec)
	ON_BN_CLICKED(BUTTON_CANCELSEL, &CYGSnifferDlg::OnBnClickedCancelsel)
	ON_BN_CLICKED(BUTTON_ABOUT, &CYGSnifferDlg::OnBnClickedAbout)
END_MESSAGE_MAP()


// CYGSnifferDlg message handlers

BOOL CYGSnifferDlg::OnInitDialog()        
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon


	ShowWindow(SW_SHOW);

	// List control default when dlg loading 
	m_listAdapterInfo.SetExtendedStyle(m_listAdapterInfo.GetExtendedStyle()|LVS_EX_HEADERDRAGDROP|
		LVS_EX_FULLROWSELECT|LVS_EX_BORDERSELECT|LVS_EX_GRIDLINES);
	m_listAdapterInfo.InsertColumn(0,L"No",LVCFMT_CENTER,50);
	m_listAdapterInfo.InsertColumn(1,L"TimeStamp",LVCFMT_CENTER,100);
	m_listAdapterInfo.InsertColumn(2,L"Length",LVCFMT_CENTER,100);

	m_listAdapterInfo.InsertColumn(3,L"Ethernet Type",LVCFMT_CENTER,120);
	m_listAdapterInfo.InsertColumn(4,L"Source Mac",LVCFMT_CENTER,150);
	m_listAdapterInfo.InsertColumn(5,L"Dest Mac",LVCFMT_CENTER,150);

	m_listAdapterInfo.InsertColumn(6,L"Protocol Type",LVCFMT_CENTER,120);
	m_listAdapterInfo.InsertColumn(7,L"Source IP",LVCFMT_LEFT,150);
	m_listAdapterInfo.InsertColumn(8,L"Dest IP",LVCFMT_LEFT,150);

	// Check box default when dlg loading 
	m_chkALL = ((CButton*)GetDlgItem(GROUPFILTER_CKECKALL));
	m_chkIP = ((CButton*)GetDlgItem(GROUPFILTER_CKECKIP));
	m_chkARP = ((CButton*)GetDlgItem(GROUPFILTER_CKECKARP));
	m_chkTCP = ((CButton*)GetDlgItem(GROUPFILTER_CKECKTCP));
	m_chkUDP = ((CButton*)GetDlgItem(GROUPFILTER_CKECKUDP));
	m_chkICMP = ((CButton*)GetDlgItem(GROUPFILTER_CKECKICMP));
	m_chkALL->SetCheck(True);
	m_chkIP->SetCheck(False);
	m_chkARP->SetCheck(False);
	m_chkTCP->SetCheck(False);
	m_chkUDP->SetCheck(False);
	m_chkICMP->SetCheck(False);

	

	// 获取当前对话框句柄
	hDlgHandle = this->GetSafeHwnd(); 

	// 获取本机所有网络适配器，并填充到Combo box中
	DispAllAdapters();

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CYGSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CYGSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CYGSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

////===============================================
// ================ controls event ==============
////
// 显示本机所有显卡到Combo 列表中
void CYGSnifferDlg::OnBnClickedFreshadapterlist()
{
	// TODO: Add your control notification handler code here
	while(m_comboAdapterList.DeleteString(0)>0);// delete all items of list control
		DispAllAdapters();
}

// 显示选中显卡信息到List Control列表中
void CYGSnifferDlg::OnBnClickedStartsniffer()
{
	OnBnClickedImmdexec();
}

void CYGSnifferDlg::OnBnClickedStopsniffer()
{
	if(m_hdlThread == NULL)
		return;
	else if(TerminateThread(m_hdlThread,-1) == 0)
		return;
	m_hdlThread = NULL;

	// TODO: Add your control notification handler code here
}


////============================================
// ================ self function ==============
//// 列出本机上的所有网卡
void CYGSnifferDlg::DispAllAdapters(void)
{
	pcap_if_t* tmpalldevs = tmpMyWinPcap.GetAdapterList();
  
	while(tmpalldevs != NULL)
	{
		USES_CONVERSION;
		m_comboAdapterList.AddString(A2W(tmpalldevs->description));
		tmpalldevs=tmpalldevs->next;
	}

	delete tmpalldevs;
}

// 返回在列表框中，被选中的网卡
pcap_if_t* CYGSnifferDlg::GetSelectedAdapter(int iSelectAdapterNo,int iTotalAdapter)
{
	int i;
	pcap_if_t* tmpAllDevs = tmpMyWinPcap.GetAdapterList();
	pcap_if_t* pSeletedAdapter = new pcap_if_t;
	pSeletedAdapter = NULL;

	/* Jump to the selected adapter */
	for(pSeletedAdapter = tmpAllDevs,i = 0;i < iSelectAdapterNo;pSeletedAdapter = pSeletedAdapter->next,i++); //********* turn to next piont *********
	

	return pSeletedAdapter;

	if(pSeletedAdapter)
	{
		delete pSeletedAdapter;
		pSeletedAdapter = NULL;
	}
}

// 显示过滤数据包的协议信息，当packet_filter过滤字符串为空时，则显示全部协议 
DWORD WINAPI Thread_GetFilterData(LPVOID param)
{
	pcap_if_t* pSelectedAdapter = (pcap_if_t*)param; // Get SelectedAdapter

	char errbuf[PCAP_ERRBUF_SIZE];
	CString errmsg;
	pcap_t* adhandle;

	/* Open the device */
	if((adhandle = pcap_open(pSelectedAdapter->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf)) == NULL)
	{
		USES_CONVERSION;
		errmsg.Format(TEXT("Unable to open the adapter. %s is not supported by WinPcap"),pSelectedAdapter->name);
		AfxMessageBox(errmsg);
		/* At this point, we don't need any more the device list. Free it */
		pcap_freealldevs(pSelectedAdapter);
		return -1;
	}

	// filter packet data(protocol)
	u_int netmask;
	
	struct bpf_program fcode;

	// get netmask
	if(NULL != pSelectedAdapter->addresses)
		netmask = ((struct sockaddr_in *)(pSelectedAdapter->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	// comppile the filter
	if(pcap_compile(adhandle,&fcode,packet_filter,1,netmask) < 0)
	{
		AfxMessageBox(TEXT("Unable to compile the packet filter. Check the syntax."));
		/* Free the device list */
        pcap_freealldevs(pSelectedAdapter);
		return -1;
	}

	// set the filter
	if(pcap_setfilter(adhandle,&fcode) < 0)
	{
		AfxMessageBox(TEXT("Error setting the filter."));
		/* Free the device list */
        pcap_freealldevs(pSelectedAdapter);
		return -1;
	}
	pcap_freealldevs(pSelectedAdapter);

	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
    
    return 0; 
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	pcap_pkthdr *header2 = new pcap_pkthdr;
	u_char *pkt_data2 = new u_char[header->len];

	memcpy(header2,header,sizeof(pcap_pkthdr));
	memcpy(pkt_data2,pkt_data,header->len);

	
	//PostMessage 只是把消息放入队列，不管其他程序是否处理都返回，然后继续执行 ;
	//而 SendMessage 必须等待其他程序处理消息后才返回，继续执行
	::PostMessage(hDlgHandle, M_MESSAGEWINPCAP, (WPARAM)header2, (LPARAM)pkt_data2); // == ** Post Message ** ==
    
		
	/*if(header2)
	{
		delete header2;
		header2 = NULL;
	}
	if(pkt_data2)
	{
		delete pkt_data2;
		pkt_data2 = NULL;
	}*/
}

// Post Message to execute program
LRESULT CYGSnifferDlg::Message_WinPcap(WPARAM wParam,LPARAM lParam)
{
	const struct pcap_pkthdr *header = (const struct pcap_pkthdr *)wParam;
	const u_char *pkt_data = (const u_char *)lParam;

	packet *pkt = new packet;
	pkt->header = header;
	pkt->pkt_data = pkt_data;

	tmpMyWinPcap.AppendPacket(pkt);// save to file -> packet.dmp 

	DispSelectedtoListCtrl(pkt); // Display 
	
	// show statistic info
	ShowStatisticInfo();

	return NULL;
	
	if(pkt)
	{
		if(pkt->header)
			delete pkt->header;
		if(pkt->pkt_data)
			delete pkt->pkt_data;
		delete pkt;
	}
}

// 显示选中的网卡数据包pkt信息到List Control列表框中
void CYGSnifferDlg::DispSelectedtoListCtrl(packet *tmp_pkt)
{
	packet *pkt = new packet;
	const struct pcap_pkthdr *header = new pcap_pkthdr;
	const u_char *pkt_data = new u_char;

	pkt = tmp_pkt;
	header = pkt->header;
	pkt_data = pkt->pkt_data;
	
	//No
	int iNoCount = m_listAdapterInfo.GetItemCount();
	int iNoDisp = iNoCount + 1;
	TCHAR strNo[10];
	_itow_s(iNoDisp,strNo,10);	

	//TimeStamp
	struct tm lTime = {0,0,0,0,0,0,0,0,0};
	struct tm *plTime = &lTime;
	char strTime[16];
	time_t local_tv_sec;
	local_tv_sec = header->ts.tv_sec;
	localtime_s(plTime,&local_tv_sec);
	strftime(strTime,sizeof strTime,"%H:%M:%S",plTime);	

	//Length
	int iLength = header->len;
	TCHAR strLength[10];
	_itow_s(iLength,strLength,10);

	//Ethernet - Mac
	ethernet_header *eth_hdr = (ethernet_header *)pkt_data;
	TCHAR   eth_srcMac[18];
	TCHAR   eth_dstMac[18];
	CString eth_strType = NULL;
	GetMacAddress(eth_srcMac,eth_hdr->srcmac);
	GetMacAddress(eth_dstMac,eth_hdr->dstmac);
	GetMacType(eth_strType,ntohs(eth_hdr->eth_type),true); // ntohs() is to swap network to host

	// IP
	ip_header *ip_hdr = (ip_header *)(pkt_data+14); // get ip pos
	TCHAR ip_srcAddr[16];
	TCHAR ip_dstAddr[16];
	CString ip_strProtocol = NULL;
	GetIPAddress(ip_srcAddr,&ip_hdr->srcaddr);
	GetIPAddress(ip_dstAddr,&ip_hdr->dstaddr);
	GetIPType(ip_strProtocol,ip_hdr->protocol,true);
	IsHTTP(pkt_data);


	//=========== show ============
	m_listAdapterInfo.InsertItem(iNoCount,strNo);
	USES_CONVERSION;
	m_listAdapterInfo.SetItemText(iNoCount,1,A2W(strTime));
	m_listAdapterInfo.SetItemText(iNoCount,2,strLength);

	m_listAdapterInfo.SetItemText(iNoCount,3,eth_strType);
	m_listAdapterInfo.SetItemText(iNoCount,4,eth_srcMac);
	m_listAdapterInfo.SetItemText(iNoCount,5,eth_dstMac);

	m_listAdapterInfo.SetItemText(iNoCount,6,ip_strProtocol);
	m_listAdapterInfo.SetItemText(iNoCount,7,ip_srcAddr);
	m_listAdapterInfo.SetItemText(iNoCount,8,ip_dstAddr);	

	if(pkt)
	{
		delete pkt;
		pkt = NULL;
	}
	if(header)
	{
		delete header;
		header = NULL;
	}
	if(pkt_data)
	{
		delete pkt_data;
		pkt_data = NULL;
	}
}

// 获取正确的Ethernet Type类型
void CYGSnifferDlg::GetMacType(CString &eth_strType, u_short eth_Type, bool isFirst) //& is to pass address
{
	if(isFirst)
		iStatistic_TotalProtocol++;

	switch(eth_Type)
	{
		case 0x0800:
			eth_strType = TEXT("IP");
			if(isFirst)
				iStatistic_TotalIP++;
			break;
		case 0x0806:
			eth_strType = TEXT("ARP");
			if(isFirst)
				iStatistic_TotalARP++;
			break;
		case 0x8035:
			eth_strType = TEXT("RARP");
			break;
		case 0x880B:
			eth_strType = TEXT("PPP");
			break;
		case 0x814C:
			eth_strType = TEXT("SNMP");
			break;
		default:
			eth_strType = TEXT("other");
			break;
	}
}
// 获取正确的Mac地址
void CYGSnifferDlg::GetMacAddress(TCHAR * eth_dMac, u_char eth_sMac[])
{
	swprintf_s(
		eth_dMac,
		18,
		TEXT("%02X-%02X-%02X-%02X-%02X-%02X"),
		eth_sMac[0],
		eth_sMac[1],
		eth_sMac[2],
		eth_sMac[3],
		eth_sMac[4],
		eth_sMac[5]);
}



// 获取正确的IP Type类型
void CYGSnifferDlg::GetIPType(CString &ip_strIP, u_short ip_Type, bool isFirst)
{
	switch(ip_Type)
	{
		case 1:
			ip_strIP = TEXT("ICMP");
			if(isFirst)
				iStatistic_TotalICMP++;
			break;
		case 6:
			ip_strIP = TEXT("TCP");
			if(isFirst)
				iStatistic_TotalTCP++;
			break;
		case 17:
			ip_strIP = TEXT("UDP");
			if(isFirst)
				iStatistic_TotalUDP++;
			break;
		default:
			ip_strIP = TEXT("other");
			break;
	}
}

// 获取IP地址
void CYGSnifferDlg::GetIPAddress(TCHAR * ip_Address, ip_address *ip_addr)
{
	swprintf_s(
		ip_Address,
		16,
		TEXT("%d.%d.%d.%d"),
		ip_addr->byte1,
		ip_addr->byte2,
		ip_addr->byte3,
		ip_addr->byte4);
}


void CYGSnifferDlg::OnNMDblclkAdapterinfo(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	packet *pkt = tmpMyWinPcap.GetPacket(pNMItemActivate->iItem+1);
	const struct pcap_pkthdr *header = pkt->header;
	const u_char *pkt_data = pkt->pkt_data;
	

	m_treeDetailInfo.DeleteAllItems();
	/*while(m_listDataInfo.DeleteString(0)>0);
	m_listDataInfo.InsertString(1,TEXT("添加数据包信息"));*/
	CString str;
	HTREEITEM hItem;

	// NO - TimeStamp
	str.Format(TEXT("NO = %d"),pNMItemActivate->iItem+1);
	hItem = m_treeDetailInfo.InsertItem(str);

	struct tm  lTime = {0,0,0,0,0,0,0,0,0};
	struct tm *plTime = &lTime;
	char strTime[9];
	time_t local_tv_sec;

	local_tv_sec = header->ts.tv_sec;
	localtime_s(plTime,&local_tv_sec);
	strftime(strTime,sizeof strTime,"%H:%M:%S",plTime); 
	USES_CONVERSION;
	str.Format(TEXT("TimeStamp = %s"),A2W(strTime));
	m_treeDetailInfo.InsertItem(str, hItem);

	// show MAC detail info
	ShowMacDetail(hItem,pkt_data);

	ethernet_header * eth_hdr = (ethernet_header *)pkt_data;
	// 如果是IP数据包，则显示IP包的详细信息；
	if(ntohs(eth_hdr->eth_type) ==0x0800)   
		ShowIPDetail(hItem,pkt_data); // show IP detail info
		
	ip_header *ip_hdr = (ip_header *)(pkt_data+14);
	if(ip_hdr->protocol == 6)	
	{
		ShowTCPDetail(hItem,pkt_data);// show TCP detail info
		if(IsHTTP(pkt_data))
			GetHTTPDetail(hItem,pkt_data);// show HTTP detail info
	}
	else if (ip_hdr->protocol == 17)
		GetUDPDetail(hItem,pkt_data);// show UDP detail info
	else if (ip_hdr->protocol == 1)
		GetICMPDetail(hItem,pkt_data);// show ICMP detail info

	
	
	// show pkt_data info(data)
	GetDataInfo(m_editDataInfo,pkt);

	*pResult = 0;
}

// 显示Mac（Ethernet）协议的详细信息
void CYGSnifferDlg::ShowMacDetail(HTREEITEM & hItem, const u_char * pkt_data)
{
	ethernet_header *mac_hdr = (ethernet_header *)pkt_data;
	hItem = m_treeDetailInfo.InsertItem(TEXT("MAC LAYER"));

	CString str = NULL;
	TCHAR mac_dstAddr[18];
	TCHAR mac_srcAddr[18];
	CString mac_strType = NULL;

	GetMacType(mac_strType,ntohs(mac_hdr->eth_type),false); // 16-bit == u_short ==  ntohs() is to swap network to host 
	str.Format(TEXT("Mac Type = %s"),mac_strType);
	m_treeDetailInfo.InsertItem(str,hItem);

	GetMacAddress(mac_srcAddr,mac_hdr->srcmac);
	str.Format(TEXT("Source Mac = %s"),mac_srcAddr);
	m_treeDetailInfo.InsertItem(str,hItem);

	GetMacAddress(mac_dstAddr,mac_hdr->dstmac);
	str.Format(TEXT("Dest Mac = %s"),mac_dstAddr);
	m_treeDetailInfo.InsertItem(str,hItem);
}

// 显示IP协议的详细信息
void CYGSnifferDlg::ShowIPDetail(HTREEITEM &hItem,const u_char *pkt_data)
{
	// =================== IP ======================
	ip_header *ip_hdr = (ip_header *)(pkt_data+14);

	hItem = m_treeDetailInfo.InsertItem(TEXT("IP LAYER"));
	CString str = NULL;
	// Version
	u_char ip_version = ip_hdr->version;
	str.Format(TEXT("Version = %d"),ip_version);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Header Length
	u_char ip_length = ip_hdr->ihl;
	str.Format(TEXT("Header Length = %d"),ip_length);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Type of service
	u_char ip_tos = ip_hdr->tos;
	str.Format(TEXT("Service Type = %0X"),ip_tos);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Total Length
	u_short ip_totalLen = ip_hdr->tot_len;
	str.Format(TEXT("Total Length = %d"),ntohs(ip_totalLen));
	m_treeDetailInfo.InsertItem(str, hItem);

	// Identification
	str.Format(TEXT("Identification = %d"),ntohs(ip_hdr->id)); 
	m_treeDetailInfo.InsertItem(str, hItem);

	// Flags
	TCHAR ip_strFlag[4];
	u_short ip_flag = (ip_hdr->flag);
	_itow_s(ip_flag,ip_strFlag,4,2);
	str.Format(TEXT("Flag = %03s"),ip_strFlag);// 填充字符串方法：CString szTemp; szTemp.Format("%06d",   n); //n=123（000123）|456（000456）
	m_treeDetailInfo.InsertItem(str, hItem);

	// Flagment offset
	u_short ip_flagoff = ip_hdr->frag_off;
	str.Format(TEXT("Flagment offset = %d"),ip_flagoff);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Time to live
	u_char ip_ttl = ip_hdr->ttl;
	str.Format(TEXT("Time to live = %d"),ip_ttl);
	m_treeDetailInfo.InsertItem(str, hItem);

	// IP Protocol
	CString ip_strProtocol = NULL;
	u_char ip_protocol = ip_hdr->protocol;
	GetIPType(ip_strProtocol,ip_protocol,false); // get ip protocol by call function -> GetIPType()
	str.Format(TEXT("IP Protocol = %s"),ip_strProtocol);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Header CheckSum
	u_short ip_chksum = ip_hdr->chk_sum;
	str.Format(TEXT("Header CheckSum = %0X"),ntohs(ip_chksum));
	m_treeDetailInfo.InsertItem(str, hItem);

	// Source IP
	TCHAR ip_srcAddr[16];
	TCHAR ip_dstAddr[16];
	GetIPAddress(ip_srcAddr,&ip_hdr->srcaddr);
	GetIPAddress(ip_dstAddr,&ip_hdr->dstaddr);
	str.Format(TEXT("Source IP = %s"),ip_srcAddr);
	m_treeDetailInfo.InsertItem(str, hItem);
	str.Format(TEXT("Dest IP = %s"),ip_dstAddr);
	m_treeDetailInfo.InsertItem(str, hItem);
}

// 显示TCP协议的详细信息
void CYGSnifferDlg::ShowTCPDetail(HTREEITEM & hItem, const u_char * pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl*4; //一行4字节，故乘以4
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data+14+ip_hdrLen);

	hItem = m_treeDetailInfo.InsertItem(TEXT("TCP LAYER"));
	CString str = NULL;


	// 源端口号-目的端口号
	u_short tcp_srcPort = tcp_hdr->src_port;
	u_short tcp_dstPort = tcp_hdr->dst_port;
	str.Format(TEXT("Source Port = %d"),ntohs(tcp_srcPort)); 
	m_treeDetailInfo.InsertItem(str, hItem);
	str.Format(TEXT("Dest Port = %d"),ntohs(tcp_dstPort)); 
	m_treeDetailInfo.InsertItem(str, hItem);

	// 序列号 - 确认号
	u_int tcp_sepNo = tcp_hdr->seq_no;
	u_int tcp_ackNo = tcp_hdr->ack_no;
	str.Format(TEXT("Seq NO = %ld"),ntohl(tcp_sepNo)); //32-bit == u_int ==  ntohl() is to swap network to host
	m_treeDetailInfo.InsertItem(str, hItem);
	str.Format(TEXT("Ack NO = %ld"),ntohl(tcp_ackNo));
	m_treeDetailInfo.InsertItem(str, hItem);

	// 数据偏移
	u_char tcp_offset = tcp_hdr->offset;
	str.Format(TEXT("Offset = %d"),tcp_offset);
	m_treeDetailInfo.InsertItem(str, hItem);

	// 6保留位
	TCHAR tcp_strOffset1[5];
	TCHAR tcp_strOffset2[3];
	u_char tcp_reserved1 = tcp_hdr->reserved_1; // first 4 bit
	_itow_s(tcp_reserved1,tcp_strOffset1,5,2);
	u_char tcp_reserved2 = tcp_hdr->reserved_2; // last 2 bit
	_itow_s(tcp_reserved2,tcp_strOffset2,3,2);
	str.Format(
		TEXT("Reserved(6 bit) = %04s%02s"), // 填充字符串方法：1、char buff[20]; memset(buff,   'x',   sizeof(buff));   
		tcp_strOffset1,                     // 填充字符串方法：2、CString szTemp; szTemp.Format("%06d",   n); //n=123（000123）|456（000456）
		tcp_strOffset2);
	m_treeDetailInfo.InsertItem(str, hItem);

	// 6标志位
	TCHAR  tcp_strflags[7]; // it is used to save string in middle
	u_char tcp_flag = tcp_hdr->flag;
	_itow_s(tcp_flag,tcp_strflags,7,2); // number to string 
	str.Format(TEXT("%06s"),tcp_strflags); // add 0 before string if there is empty

	CString strFlags = str; // save str

	
	swprintf(           // ntohs()  net--->host format
		tcp_strflags,
		7,
		TEXT("%c%c%c%c%c%c"),
		str[5],
		str[4],
		str[3],
		str[2],
		str[1],
		str[0]);

	str.Format(TEXT("Flags = %s"),tcp_strflags);
	HTREEITEM childhItem = m_treeDetailInfo.InsertItem(str,hItem); // create a new child tree

	str.Format(TEXT("URG = %c"),strFlags[5]);
	m_treeDetailInfo.InsertItem(str,childhItem);
	str.Format(TEXT("ACK = %c"),strFlags[4]);
	m_treeDetailInfo.InsertItem(str,childhItem);
	str.Format(TEXT("PSH = %c"),strFlags[3]);
	m_treeDetailInfo.InsertItem(str,childhItem);
	str.Format(TEXT("RST = %c"),strFlags[2]);
	m_treeDetailInfo.InsertItem(str,childhItem);
	str.Format(TEXT("SYN = %c"),strFlags[1]);
	m_treeDetailInfo.InsertItem(str,childhItem);
	str.Format(TEXT("FIN = %c"),strFlags[0]);
	m_treeDetailInfo.InsertItem(str,childhItem);

	// 窗口大小
	u_short tcp_wndsize = tcp_hdr->wnd_size;
	str.Format(TEXT("Windows size = %d"),ntohs(tcp_wndsize));
	m_treeDetailInfo.InsertItem(str,hItem);

	// 校验和
	u_short tcp_checksum = tcp_hdr->chk_sum;
	str.Format(TEXT("CheckSum = %d"),ntohs(tcp_checksum));
	m_treeDetailInfo.InsertItem(str,hItem);

	// 紧急指针
	u_short tcp_urgpoint = tcp_hdr->urgt_p;
	str.Format(TEXT("Urgent Point = %d"),ntohs(tcp_urgpoint));
	m_treeDetailInfo.InsertItem(str,hItem);
}

// 显示UDP协议的详细信息
void CYGSnifferDlg::GetUDPDetail(HTREEITEM & hItem, const u_char * pkt_data)
{	 
	ip_header *ip_hdr = (ip_header *)(pkt_data+14);
	u_short ip_hdrLen = ip_hdr->ihl*4;
	udp_header *udp_hdr = (udp_header *)(pkt_data+14+ip_hdrLen);

	hItem = m_treeDetailInfo.InsertItem(TEXT("UDP LAYER"));
	CString str = NULL;

	// Port
	u_short udp_srcPort = udp_hdr->src_port;
	u_short udp_dstPort = udp_hdr->dst_port;
	str.Format(TEXT("Source Port = %d"),ntohs(udp_srcPort));
	m_treeDetailInfo.InsertItem(str,hItem);
	str.Format(TEXT("Dest Port = %d"),ntohs(udp_dstPort));
	m_treeDetailInfo.InsertItem(str,hItem);

	// Header Length
	u_short udp_hdrLen = udp_hdr->uhl;
	str.Format(TEXT("Header Length = %d"),ntohs(udp_hdrLen));
	m_treeDetailInfo.InsertItem(str,hItem);

	// 校验和
	u_short udp_checksum = udp_hdr->chk_sum;
	str.Format(TEXT("CheckSum = %d"),ntohs(udp_checksum));
	m_treeDetailInfo.InsertItem(str,hItem);
}


// 显示ICMP协议的详细信息
void CYGSnifferDlg::GetICMPDetail(HTREEITEM & hItem, const u_char * pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data+14);
	u_short ip_hdrLen = ip_hdr->ihl*4;
	icmp_header *icmp_hdr = (icmp_header *)(pkt_data+14+ip_hdrLen);

	hItem = m_treeDetailInfo.InsertItem(TEXT("ICMP LAYER"));
	CString str = NULL;

	// 类型
    u_char icmp_type = icmp_hdr->type;
	str.Format(TEXT("Type = %d"),icmp_type);
	m_treeDetailInfo.InsertItem(str,hItem);

	// 代码
	u_char icmp_code = icmp_hdr->code;
	str.Format(TEXT("Code = %d"),icmp_code);
	m_treeDetailInfo.InsertItem(str,hItem);

	// 检验和
	u_short icmp_checksum = icmp_hdr->chk_sum;
	str.Format(TEXT("CheckSum = %d"),ntohs(icmp_checksum));
	m_treeDetailInfo.InsertItem(str,hItem);
}

// 显示HTTP协议的详细信息====================================================================================================================================================================================
void CYGSnifferDlg::GetHTTPDetail(HTREEITEM & hItem, const u_char *pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data+14);
	u_short ip_hdrLen = ip_hdr->ihl*4;
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data+14+ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->offset*4;


	u_char *http_pkt = (u_char *)(pkt_data+14+ip_hdrLen+tcp_hdrLen);	
	u_short http_pktLen = ntohs(ip_hdr->tot_len) - (ip_hdrLen+tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);

	//http_packet * http_pktHdr = new http_packet ;// HTTP packet's  struct
	vector<CString> strVecRequestHttp; // 定义请求头容器
	vector<CString> strVecRespondHttp; // 定义响应头容器
	CString chrVecTmp = NULL; // 声明存入容器的临时字符
	CString strVecTmp = NULL; // 声明存入容器的临时字符串

	u_char * pchrHttpAllData = NULL; //定义HTTP协议包的起始位置，包括请求头或响应头都可
	u_char * pchrHttpRequestPos = NULL; //定义HTTP协议包的请求头的起始位置
	u_char * pchrHttpRespondPos = NULL; //定义HTTP协议包的响应头的起始位置
	pchrHttpAllData = http_pkt; //赋值得到HTTP协议包的开始位置

	CString strHttpALLData = NULL;//定义HTTP协议包的数据包,包括请求头或响应头都可
	CString strHttpRequestData = NULL;//定义HTTP协议包的请求头的数据
	CString strHttpRespondData = NULL;//定义HTTP协议包的响应头的数据

	u_short httpAllPos = 0;
	u_short httpAllLen = 0;
	httpAllLen = http_pktLen;

	if(IsHTTP(pkt_data)) // check is http
	{	
		// show request to tree
		hItem = m_treeDetailInfo.InsertItem(TEXT("HTTP LAYER"));

		if(*pkt_data == 'H') // 如果第一个字符为H，即可能以HTTP开头的，则为响应头，否则应为请求头
		{
			for(int i=0;i<httpAllLen;i++) // get http_Get data
			{
				chrVecTmp.Format(TEXT("%c"),pchrHttpAllData[i]); // format
				strHttpRespondData += chrVecTmp;//记录完整的HTTP响应头的数据

				chrVecTmp.Format(TEXT("%c"),pchrHttpAllData[i]); //记录每一行的内容，并保存在临时字符串中
				strVecTmp += chrVecTmp;
				if(i>2 && pchrHttpAllData[i-1]==13 && pchrHttpAllData[i]==10) //根据回车换行符判断，并把每行保存在vector数组中
				{
					strVecRespondHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}	

			HTREEITEM childhItem = m_treeDetailInfo.InsertItem(TEXT("Request Header:"),hItem);
			for(u_short irequest=0;irequest<strVecRequestHttp.size();irequest++)			
				m_treeDetailInfo.InsertItem(strVecRequestHttp[irequest],childhItem);
		}
		else
		{
			for(int i=0;i<httpAllLen;i++) // get http_Get data
			{
				chrVecTmp.Format(TEXT("%c"),pchrHttpAllData[i]); // format
				strHttpRequestData += chrVecTmp;//记录完整的HTTP响应头的数据

				chrVecTmp.Format(TEXT("%c"),pchrHttpAllData[i]); //记录每一行的内容，并保存在临时字符串中
				strVecTmp += chrVecTmp;
				if(i>2 && pchrHttpAllData[i-1]==13 && pchrHttpAllData[i]==10) //根据回车换行符判断，并把每行保存在vector数组中
				{
					strVecRespondHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}

			HTREEITEM childhItem = m_treeDetailInfo.InsertItem(TEXT("Respond Header:"),hItem);
			for(u_short irespond=0;irespond<strVecRespondHttp.size();irespond++)			
				m_treeDetailInfo.InsertItem(strVecRespondHttp[irespond],childhItem);
		}		
	}	



	



	
}

// 判断该协议是否为HTTP协议
bool CYGSnifferDlg::IsHTTP(const u_char *pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data+14);
	u_short ip_hdrLen = ip_hdr->ihl*4;
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data+14+ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->offset*4;

	u_char *http_pkt = (u_char *)(pkt_data+14+ip_hdrLen+tcp_hdrLen);	
	u_short http_pktLen = ntohs(ip_hdr->tot_len) - (ip_hdrLen+tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);
	
	CString chrTmp = NULL;
	CString strTmp = NULL;
	CString strHttp = NULL;

	int httpPos = 0;

	if(ip_hdr->protocol == 6)
	{
		for(int i=0;i<http_pktLen;i++) // 仅提取第一行是否含有HTTP字符串
		{
			chrTmp.Format(TEXT("%c"),http_pkt[i]);
			strTmp += chrTmp;
			if(i>2 && http_pkt[i-1]==13 && http_pkt[i]==10)
				break;
		}
		//AfxMessageBox(strTmp);
		httpPos = strTmp.Find(TEXT("HTTP"),0);

		if(httpPos != -1 && httpPos != 65535) // 如果第一行含有字符串HTTP，则为HTTP协议
		{
			iStatistic_TotalHTTP++;
			return true;
		}
			
		else
			return false;
		
	}
	return false;
}

// 显示Packet Data数据信息，最下方控件显示；
void CYGSnifferDlg::GetDataInfo(CEdit & eText, packet *pkt)
{
	const struct pcap_pkthdr *header = pkt->header;
	const u_char *pkt_data = pkt->pkt_data;
	u_int pkt_dataLen = header->len; // 得到单个Packet_Data(注意：不是packet)数据包的长度
	
	CString strText = NULL;
	CString chrAppend = NULL;

	u_int eRows = 0;

	for(u_short i=0; i<pkt_dataLen; i++)
	{
		CString strAppend = NULL;
		if(0 == (i%16)) // 取余，换行
		{
			eRows++;

			if(0 == i)
			{
				strText +=chrAppend;
				strAppend.Format(TEXT(" 0X%04X ->  "),eRows);
				strText += strAppend;
			}
			else
			{ 
				strText +=TEXT("==>> ") +chrAppend;
				strAppend.Format(TEXT("\x0d\x0a 0X%04X ->  "),eRows); //0x0d:回车; 0x0a:换行;0X:表示16进制显示;%04x表示以4位的16进制显示并以0填充空位; eRows即显示行数（16进制格式显示）
				strText += strAppend;
			}
			chrAppend = ""; // reset null
		}
		strAppend.Format(TEXT("%02x "),pkt_data[i]);
		strText += strAppend;
		

		if(i>2 && pkt_data[i-1]==13 && pkt_data[i]==10)//如果遇到回车、换行，则直接继续，以免使显示字符换行
			continue;
		strAppend.Format(TEXT("%c"),pkt_data[i]);
		chrAppend += strAppend;
		
	}
	if(chrAppend !="")
		strText +=TEXT("==>> ") +chrAppend;

	eText.SetWindowTextW(strText);
}


// 在“数据统计”组中，显示接收到的各种协议数据包统计信息
void CYGSnifferDlg::ShowStatisticInfo(void)
{
	CString strALL = NULL;
	CString strIP = NULL;
	CString strARP = NULL;
	CString strTCP = NULL;
	CString strUDP = NULL;
	CString strICMP = NULL;
	CString strHTTP = NULL;
	CString strFTP = NULL;
	CString strSMTP = NULL;

	strALL.Format(TEXT("%ld"),iStatistic_TotalProtocol);
	this->SetDlgItemTextW(GROUPSTATISTICS_EDITALL,strALL);

	strIP.Format(TEXT("%ld"),iStatistic_TotalIP);
	this->SetDlgItemTextW(GROUPSTATISTICS_EDITIP,strIP);

	strARP.Format(TEXT("%ld"),iStatistic_TotalARP);
	this->SetDlgItemTextW(GROUPSTATISTICS_EDITARP,strARP);

	strTCP.Format(TEXT("%ld"),iStatistic_TotalTCP);
	this->SetDlgItemTextW(GROUPSTATISTICS_EDITTCP,strTCP);

	strUDP.Format(TEXT("%ld"),iStatistic_TotalUDP);
	this->SetDlgItemTextW(GROUPSTATISTICS_EDITUDP,strUDP);

	strICMP.Format(TEXT("%ld"),iStatistic_TotalICMP);
	this->SetDlgItemTextW(GROUPSTATISTICS_EDITICMP,strICMP);

	strHTTP.Format(TEXT("%ld"),iStatistic_TotalHTTP);
	this->SetDlgItemTextW(GROUPSTATISTICS_EDITHTTP,strHTTP);

	strFTP.Format(TEXT("%ld"),iStatistic_TotalFTP);
	this->SetDlgItemTextW(GROUPSTATISTICS_EDITFTP,strFTP);

	strSMTP.Format(TEXT("%ld"),iStatistic_TotalSMTP);
	this->SetDlgItemTextW(GROUPSTATISTICS_EDITSMTP,strSMTP);
	
}

// 设置过滤器，并在List Constrol列表框中显示出过滤出的信息
void CYGSnifferDlg::CheckedFiltertoListCtrl()
{
	if(m_chkALL->GetCheck() == BST_CHECKED) // get all protocol 
	{
		char * pstr = "";
		packet_filter = pstr;
	}
	else if(m_chkIP->GetCheck() == BST_CHECKED) // get  ip
	{	
		char * pstr = "ip";
		packet_filter = pstr;
	}	
	else if(m_chkARP->GetCheck() == BST_CHECKED && m_chkIP->GetCheck() == BST_UNCHECKED) // get only arp
	{	
		char * pstr = "arp";
		packet_filter = pstr;
	}	
	else if(m_chkARP->GetCheck() == BST_CHECKED && m_chkIP->GetCheck() == BST_CHECKED) // get ip and arp
	{	
		char * pstr = "ip and arp";
		packet_filter = pstr;
	}	
	else if(m_chkTCP->GetCheck() == BST_CHECKED && m_chkIP->GetCheck() == BST_UNCHECKED) // get only tcp 
	{	
		char * pstr = "ip and tcp";
		packet_filter = pstr;
	}	
	else if(m_chkUDP->GetCheck() == BST_CHECKED && m_chkALL->GetCheck() == BST_UNCHECKED)
	{	
		char * pstr = "ip and udp";
		packet_filter = pstr;
	}	
	else if(m_chkICMP->GetCheck() == BST_CHECKED && m_chkALL->GetCheck() == BST_UNCHECKED)
	{	
		char * pstr = "ip and icmp";
		packet_filter = pstr;
	}	
	
	UpdateData(true);  // 把控件的值传给对应的变量
	UpdateData(false); // 把变量的值传递给控件
}

// 选择了过滤协议后，立即执行过滤协议，并显示出过滤后的协议信息
void CYGSnifferDlg::OnBnClickedImmdexec()
{
	CheckedFiltertoListCtrl(); // 调用过滤器，默认是选中ALL全部协议

	int iSelectAdapterNo = m_comboAdapterList.GetCurSel();
	int iTotalAdapter = m_comboAdapterList.GetCount();
	if(iSelectAdapterNo < 0 || iSelectAdapterNo > (iTotalAdapter-1))
	{
		AfxMessageBox(TEXT("Interface number out of range..."));
		return;
	}

	pcap_if_t* pSelectAdapter = GetSelectedAdapter(iSelectAdapterNo,iTotalAdapter);

	CloseHandle(m_hdlThread);

	m_hdlThread = CreateThread(NULL,0,Thread_GetFilterData,(LPVOID)pSelectAdapter,0,&dwThread);


}

// 选择了过滤协议后，又点击了取消选择，则全部清零
void CYGSnifferDlg::OnBnClickedCancelsel()
{
	m_chkALL->SetCheck(False);
	m_chkIP->SetCheck(False);
	m_chkARP->SetCheck(False);
	m_chkTCP->SetCheck(False);
	m_chkUDP->SetCheck(False);
	m_chkICMP->SetCheck(False);
}

void CYGSnifferDlg::OnBnClickedAbout()
{
	// TODO: Add your control notification handler code here
	// 退出时，弹出作者、版本信息框
	CDialog dlg(ABOUTBOX_INFO);
	dlg.DoModal();
}
