rule Bypass_Sample {
    meta: description = "Evasion bypass patterns targeting memory addresses and jumps"
    meta: cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 0A ?? 5A 8B 4F ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF 07 9C ?? ?? ?? ?? 85 C0 FF 0D F3 ?? }

    condition: any
}