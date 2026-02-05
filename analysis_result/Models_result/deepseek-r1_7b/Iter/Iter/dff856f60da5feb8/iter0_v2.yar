rule Bypass_EB
{
    meta:
        description = "Bypassing ExitProcess by skipping stack push of EB"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 5A 74 12 FF 8C 6A 40 53 }
        $pattern1 = { 85 C0 5A 74 12 FF 8C 6A 40 5D }
        $pattern2 = { 85 C0 5A 74 12 FF 8C 6A 40 5E }

    condition:
        any of them
}