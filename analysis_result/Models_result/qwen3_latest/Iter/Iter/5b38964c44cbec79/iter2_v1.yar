rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B }  // test eax, eax + je + push
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // call to ExitProcess (address wildcard)
        $pattern2 = { 6A 5B 5A 8B CE E8 ?? }  // push/pop/mov/call sequence

    condition:
        any of them
}