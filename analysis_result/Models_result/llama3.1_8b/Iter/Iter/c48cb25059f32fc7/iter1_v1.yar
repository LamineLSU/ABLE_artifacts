rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } // test+jmp
        $pattern1 = { E8 B4 AE FE FF 83 C4 10 85 C0 0F 84 ?? ?? ?? ?? } // call exit function + ...
        $pattern2 = { 6A 01 5A 8B CE E8 C9 BC FF FF 85 C0 } // push + pop + mov + ...

    condition:
        any of them
}