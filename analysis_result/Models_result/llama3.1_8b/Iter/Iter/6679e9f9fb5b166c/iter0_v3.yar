rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=8B859CFDFFFF ?? ?? 33C0 E8A591FEFF ????+0,action0=skip,bp1=E8A591FEFF ?? 6A00 E8E4B7FEFF ???+0,action1=skip,bp2=33C0 E8D9CEFFFF 8B859CFDFFFF ????+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 9C FD FF FF ?? ?? 33 C0 E8 A5 91 FE FF ?? }
        $pattern1 = { E8 A5 91 FE FF ?? 6A 00 E8 E4 B7 FE FF ?? }
        $pattern2 = { 33 C0 E8 D9 CE FF FF 8B 85 9C FD FF FF ?? }

    condition:
        any of them
}