rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 8B CE }  // test eax, eax + je + mov ecx, esi
        $pattern1 = { 0F 84 ?? ?? ?? ?? }  // near je (conditional check)
        $pattern2 = { E8 ?? ?? ?? ?? 50 }  // call + push (post-check execution)

    condition:
        any of them
}