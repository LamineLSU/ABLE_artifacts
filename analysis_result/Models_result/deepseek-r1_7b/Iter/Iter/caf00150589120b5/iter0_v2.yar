rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns from exit process trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF EA 00 00 01 10 74 12 6A 5B 00 00 00 5B 5A ED 8B CE EC E8 25 05 00 CA 00 00 01 F8 03 C3 AD EA EB BA 04 01 00 00 ED 00 00 01 04 FF 88 88 A0 01 00 CA DD 00 00 01 10 E8 C8 FF FF FF CA CE 00 E0 61 2A }
        
        $pattern1 = { 03 C3 AD EA EB BA 04 01 00 00 ED 00 00 01 04 FF 88 88 A0 01 00 CA DD 00 00 01 10 E8 C8 FF FF FF CA CE 00 E0 61 2A }
        
        $pattern2 = { 74 12 00 00 01 10 6A 5B 00 00 00 5B 5A ED 8B CE EC E8 25 05 00 CA 00 00 01 F8 03 C3 AD EA EB BA 04 01 00 00 ED 00 00 01 04 FF 88 88 A0 01 00 CA DD 00 00 01 10 E8 C8 FF FF FF CA CE 00 E0 61 2A }
    condition:
        any of them
}