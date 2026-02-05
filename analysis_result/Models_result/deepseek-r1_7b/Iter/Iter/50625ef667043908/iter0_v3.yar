rule Bypass_Sample {
    meta:
        description = "Bypass conditional EAX-based jump"
        cape_options = "bp0=$pattern2+0,action0=skip,bp1=$pattern3+0,action1=skip,bp2=$pattern4+0,action2=skip,count=0"

    strings:
        $pattern2 = { 00 FA 61 A9 FF 75 08 FF 15 3C E1 1E 00 E8 FF FF 3F 8F 0F EF FF FF 15 40 E1 1E 00 FF 75 08 FF 75 08 FF 75 08 FF 75 08 FF 75 08 FF 75 08 FF 75 08 FF 75 08 FF 75 08 FF 75 08 }
    condition:
        any of them
}