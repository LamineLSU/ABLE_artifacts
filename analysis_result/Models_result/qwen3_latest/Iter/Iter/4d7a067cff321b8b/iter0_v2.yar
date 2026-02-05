rule ExitPattern1
{
    meta:
        description = "Pattern 1: Call to ExitProcess with preceding push ebx"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 53 E8 ?? ?? ?? ?? }
    condition:
        all of them
}