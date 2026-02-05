rule FunctionPrologueSetup
{
    meta:
        description = "Standard function prologue setup"
        cape_options = "bp0=$setup+0,action0=skip,count=0"
    strings:
        $setup = { 55 8B EC FF 75 08 }
    condition:
        $setup
}