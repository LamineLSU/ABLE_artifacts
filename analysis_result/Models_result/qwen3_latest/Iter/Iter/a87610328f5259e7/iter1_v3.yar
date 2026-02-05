rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 ?? ?? ?? ?? }  // test eax, eax + je + call
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }     // test eax, eax + je (different offset)
        $pattern2 = { A1 88 85 D2 00 85 C0 74 07 }  // mov eax, [00D28588h] + test + je

    condition:
        any of them
}