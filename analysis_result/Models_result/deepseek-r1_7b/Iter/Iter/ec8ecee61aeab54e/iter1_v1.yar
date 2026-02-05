rule Bypass_Esc0x1B7A_0x1F5D_0x1F63
{
    meta:
        description = "Evasion bypass rule targeting calls to 0x1B7A, 0x1F5D and 0x1F63"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? 83 C4 ?? 85 C0 ?? ?? ?? }
        $pattern1 = { 7B 00 00 00 00 00 7A ?? ?? ?? 0F 63 ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?F 4C ?? ?? ?? }

    condition:
        any of them
}