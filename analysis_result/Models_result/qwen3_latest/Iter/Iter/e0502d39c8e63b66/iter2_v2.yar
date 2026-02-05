rule ProcessInitializationCheck
{
    meta:
        description = "Detects process initialization code that calls GetCommandLineA, GetStartupInfoA, and GetModuleHandleA"
        cape_options = "bp0=$get_cmdline+0,action0=skip,bp1=$get_startup+0,action1=skip,bp2=$get_module+0,action2=skip,count=0"
        author = "YourName"
        date = "2025-04-05"
    strings:
        $get_cmdline = { FF 15 BC A0 41 00 }
        $get_startup = { FF 15 C0 A0 41 00 }
        $get_module = { FF 15 44 A2 41 00 }
    condition:
        all of ($get_cmdline, $get_startup, $get_module)
}