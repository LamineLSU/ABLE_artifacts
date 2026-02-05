rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B }  // test eax, eax + je + push
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // ExitProcess call (relative address)
        $pattern2 = { E8 ?? ?? ?? ?? 85 C0 }  // Call + test eax, eax (evasion check)

    condition:
        any of them
}