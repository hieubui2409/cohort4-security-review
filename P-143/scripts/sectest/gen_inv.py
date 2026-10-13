import sys
num, desc, out = sys.argv[1], sys.argv[2], sys.argv[3]
code = sys.argv[4] if len(sys.argv) > 4 else "INV-LOP-GEN"
xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<HDon><DLHDon Id="data">
<TTChung><PBan>2.0.0</PBan><THDon>HÓA ĐƠN GIÁ TRỊ GIA TĂNG</THDon><KHMSHDon>1</KHMSHDon><KHHDon>C26TAB</KHHDon>
<SHDon>{num}</SHDon><NLap>2026-09-20</NLap><DVTTe>VND</DVTTe><HTTToan>TM/CK</HTTToan>
<TTKhac><TTin><TTruong>Số PO</TTruong><KDLieu>string</KDLieu><DLieu>PO-SECTEST-INJ1</DLieu></TTin></TTKhac></TTChung>
<NDHDon>
<NBan><Ten>Công ty TNHH ABC</Ten><MST>0312345678</MST><DChi>12 Nguyễn Trãi, Q1, HCM</DChi></NBan>
<NMua><Ten>Công ty Xe X</Ten><MST>0109876543</MST><DChi>1 Phạm Văn Đồng, Hà Nội</DChi></NMua>
<DSHHDVu><HHDVu><TChat>1</TChat><STT>1</STT><MHHDVu>{code}</MHHDVu>
<THHDVu>{desc}</THHDVu>
<DVTinh>cái</DVTinh><SLuong>8</SLuong><DGia>1400000</DGia><ThTien>11200000</ThTien><TSuat>10%</TSuat></HHDVu></DSHHDVu>
<TToan><THTTLTSuat><LTSuat><TSuat>10%</TSuat><ThTien>11200000</ThTien><TThue>1120000</TThue></LTSuat></THTTLTSuat>
<TgTCThue>11200000</TgTCThue><TgTThue>1120000</TgTThue><TgTTTBSo>12320000</TgTTTBSo>
<TgTTTBChu>Mười hai triệu ba trăm hai mươi nghìn đồng</TgTTTBChu></TToan></NDHDon>
</DLHDon><DSCKS><NBan/></DSCKS></HDon>'''
open(out, "w", encoding="utf-8").write(xml)
print("wrote", out, len(xml), "bytes")
