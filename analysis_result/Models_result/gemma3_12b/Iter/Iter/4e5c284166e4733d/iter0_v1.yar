rule Bypass_FS_Check_1
{
    meta:
        description = "Bypass FS register check (JNE)"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 64 8B 45 30 85 C0 74 06 }

    condition:
        any of them
}