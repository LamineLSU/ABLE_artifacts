rule EvasionBypass {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 C0 0F 84 FF D0 ?? EA EB EB CA EA }
        
        $pattern1 = { EC 6A 35 5A 8B CE E8 ?? AD EB EB EA DD EB 0C EC DD EA 14 }
        
        $pattern2 = { 6A D3 00 5E ?? 00 00 00 D3 EB AD E8 }

    condition:
        any of them
}