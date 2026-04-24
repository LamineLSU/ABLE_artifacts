rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } //Bypass initial check before 01376183
        $pattern1 = { FF 15 88 A0 37 01 53 6A 40 53 68 40 11 37 01 } // Bypass FF15 at 013761F8
        $pattern2 = { E8 C8 FF FF FF 59 FF 75 08 } // Bypass call at 0040E7F6

    condition:
        any of them
}