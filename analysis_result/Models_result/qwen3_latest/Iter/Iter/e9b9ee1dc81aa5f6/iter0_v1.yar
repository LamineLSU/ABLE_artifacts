rule ShellExecuteCall
{
    meta:
        description = "Detects a call to ShellExecuteW with parameter preparation"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 6A 00 50 50 50 50 6A 00 50 FF 15 ?? ?? ?? ?? }
    condition:
        all of them
}