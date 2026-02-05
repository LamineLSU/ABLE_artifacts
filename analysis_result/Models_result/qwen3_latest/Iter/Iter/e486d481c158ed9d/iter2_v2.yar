rule FunctionPrologue
{
    meta:
        description = "Function prologue used to set up stack frame"
        cape_options = "bp0=$prologue+0,action0=skip,count=0"
    strings:
        $prologue = { 55 8B EC FF 75 08 }
    condition:
        $prologue
}