rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 4D FC }  // test eax, je + mov ebp
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  // test eax, je with relative offset
        $pattern2 = { 83 F8 01 74 12 8B 4D FC }  // cmp eax, 1 + je + mov ebp

    condition:
        any of them
}