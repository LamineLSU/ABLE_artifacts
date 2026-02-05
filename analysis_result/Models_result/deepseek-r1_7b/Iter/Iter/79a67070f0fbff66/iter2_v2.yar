rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific function calls"
        cape_options = "bp0=E8,8D,9A,FF,FF,EBC;action0=skip,bp1=8B55C4,E88D9AFFFF,action1=skip,bp2=E85F880000,FF15F0506100,action2=skip,count=0"

    strings:
        $pattern0 = { E8 8D 9A FF FF EB }
        $pattern1 = { 8B 55 C4 E8 8D 9A FF FF }
        $pattern2 = { E8 5F 88 00 00 FF 15 F0 50 61 00 }

    condition:
        any of them
}