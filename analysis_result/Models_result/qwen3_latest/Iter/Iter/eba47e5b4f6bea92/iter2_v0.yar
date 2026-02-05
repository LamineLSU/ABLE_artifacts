rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 8B 45 ?? }  // test eax, eax + je + mov ecx
        $pattern1 = { 8B CE FF 15 ?? ?? ?? ?? }  // mov ecx, esi + call dword ptr
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? }  // push dword ptr + call with variable offset

    condition:
        any of them
}