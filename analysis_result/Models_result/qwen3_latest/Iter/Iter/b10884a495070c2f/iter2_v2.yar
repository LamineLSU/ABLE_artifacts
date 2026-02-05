rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 DB 74 1B }  // test ebx, ebx + je
        $pattern1 = { 85 C0 75 0E }  // test eax, eax + jne
        $pattern2 = { E8 90 F6 FF FF 85 DB 74 1B }  // call + test ebx, ebx + je

    condition:
        any of them
}