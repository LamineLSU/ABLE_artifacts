rule Bypass_Sample
{
    meta:
        description = "Evasion bypass through conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF E8 F4 ?? ?? ?? 3F EA 7A ?? 5B FF 5E FE C8 01 5E 5C FE CA FE CD ?? ?? FF D9 ?? ?? ?? ?? 2D }
        
        $pattern1 = { 6A ?? 3C ?? ?? 8D 84 F8 04 ?? E8 ?? FE F8 FE F8 5B ?? ?? FF D9 ?? ?? FF D9 }

        $pattern2 = { 6A ?? 18 8D 84 F8 ?? ?? E8 ?? FE F8 FE F8 5B FF C8 ?? FF D9 }
    condition:
        any of them
}