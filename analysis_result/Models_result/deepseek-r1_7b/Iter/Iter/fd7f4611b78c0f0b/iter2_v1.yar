rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting conditional jumps and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8C8FFFFFF 5A 8BCE 0F8433FDFFFF FF7508 59 ?? ?? ?? ?? 8BE5 5D }
        $pattern2 = { FF15ACB04100 8BC7 0086E80h E80D0C0000 }

    condition:
        any of them
}