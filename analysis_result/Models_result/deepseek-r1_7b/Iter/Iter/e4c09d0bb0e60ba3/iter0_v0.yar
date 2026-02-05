rule Bypass_Sample {
    meta:
        description = "Evasion bypass rules targeting ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? 74 12 6A ?? 5A 8B CE E8 25 FF D9 0F 84 74 1B 8D 43 EA 03 C3 AD BA 04 ?? ?? 8E 2C FF D8 }
        $pattern1 = { 6A ?? 5A 8B CE E8 2F FF 1F 0F 84 74 19 8D 43 EA 03 C3 AD BA 04 ?? ?? 8E 2C FF D8 }
        $pattern2 = { 6A ?? 5A 8B CE E8 1F FF 0F 0F 84 74 19 8D 43 EA 03 C3 AD BA 04 ?? ?? 8E 2C FF D8 }

    condition:
        any of them
}