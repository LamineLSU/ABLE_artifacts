rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using specific exit check and conditional jump patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = LEA 0x4C98h,0x4C98h,LEA 0x4C98h,0x4C98h
        $pattern1 = 8B5514,8B5514
        $pattern2 = E8740A0000,E8740A0000

    condition:
        any of them
}