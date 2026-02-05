rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? }  // Call to IsWindowVisible
        $pattern1 = { 85 C0 74 10 8B 4D F8 }  // test eax, eax + je + mov
        $pattern2 = { 6A 00 FF 15 ?? ?? ?? ?? }  // push 00h + call ExitProcess

    condition:
        any of them
}