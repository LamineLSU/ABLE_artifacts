rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 53 ?? ?? ?? ?? 8B 45 5E }
        $pattern1 = { E8 EC 7A FF FF 00 83 6C 00 82 5E 7F 00 }
        $pattern2 = { 6A 5B 8B CE ?? ?? ?? ?? 85 C0 0F 84 53 }

    condition:
        any of them
}