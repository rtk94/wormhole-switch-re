/*
 * gobridge_scsi.d -- log every SCSITask a process sends (CDB, data out, data in,
 * status, sense), tagged with the calling OTiTransporter method.
 *
 * Usage (OS X 10.6, i386 process; 10.6 has no pgrep):
 *   P=$(ps -axo pid=,comm= | awk '/GoBridgeDemon$/{print $1}')
 *   sudo dtrace -s gobridge_scsi.d -p $P -o trace.log
 * To stop it from a non-root shell (e.g. over ssh), keep a copy of
 * /usr/bin/true named wh-stop and run it: the exec probe at the end exits.
 * See docs/upipe-protocol.md for what the logged CDBs mean.
 *
 * Line formats (ts = walltimestamp ns, tid = thread id):
 *   C  ts tid fn cdblen  <cdb hex>
 *   G  ts tid dir xfer addr          (dir 0=none 1=out 2=in)
 *   O  ts tid len  <data hex>        (data out, <=16 B inline)
 *   I  ts tid len  <data hex>        (data in,  <=16 B inline)
 *   X  ts tid ret status realized    (ExecuteTaskSync return)
 *   S  ts tid  <18 B sense hex>      (only when status != 0)
 * Larger buffers are emitted as "OB ts tid len" / "IB ts tid len" followed by a
 * tracemem() hex dump of a fixed tier size; only the first len bytes are valid.
 */
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option switchrate=20hz
#pragma D option dynvarsize=8m

pid$target::OTiTransporter??SendSCSICommandSendData*:entry   { self->fn = "send"; }
pid$target::OTiTransporter??SendSCSICommandReceiveData*:entry { self->fn = "recv"; }
pid$target::OTiTransporter??SendSCSICommandSendData*:return,
pid$target::OTiTransporter??SendSCSICommandReceiveData*:return { self->fn = 0; }

pid$target::SCSITaskClass??SetCommandDescriptorBlock*:entry
{
	self->dir = 0; self->xfer = 0; self->addr = 0;
	this->c = (uint8_t *)copyin(arg1, 16);
	printf("C %d %d %s %d  %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
	    walltimestamp, tid, self->fn != 0 ? self->fn : "-", arg2,
	    this->c[0], this->c[1], this->c[2], this->c[3], this->c[4], this->c[5], this->c[6], this->c[7],
	    this->c[8], this->c[9], this->c[10], this->c[11], this->c[12], this->c[13], this->c[14], this->c[15]);
}

/* (this, IOVirtualRange *list, UInt8 count, UInt64 xfer [arg3 lo, arg4 hi], UInt8 dir) */
pid$target::SCSITaskClass??SetScatterGatherEntries*:entry
{
	this->r = (uint32_t *)copyin(arg1, 8);
	self->addr = this->r[0];
	self->xfer = arg3;
	self->dir = arg5;
	printf("G %d %d %d %d %d %x\n", walltimestamp, tid, arg2, arg5, arg3, this->r[0]);
}

/* (this, SCSI_Sense_Data *, SCSITaskStatus *, UInt64 *realized) */
pid$target::SCSITaskClass??ExecuteTaskSync*:entry
{
	self->sensep = arg1; self->statp = arg2; self->realp = arg3; self->inexec = 1;
}

pid$target::SCSITaskClass??ExecuteTaskSync*:entry
/self->dir == 1 && self->xfer > 0 && self->xfer <= 16/
{
	this->d = (uint8_t *)copyin(self->addr, 16);
	printf("O %d %d %d  %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
	    walltimestamp, tid, self->xfer,
	    this->d[0], this->d[1], this->d[2], this->d[3], this->d[4], this->d[5], this->d[6], this->d[7],
	    this->d[8], this->d[9], this->d[10], this->d[11], this->d[12], this->d[13], this->d[14], this->d[15]);
}
pid$target::SCSITaskClass??ExecuteTaskSync*:entry
/self->dir == 1 && self->xfer > 16 && self->xfer <= 512/
{ printf("OB %d %d %d\n", walltimestamp, tid, self->xfer); tracemem(copyin(self->addr, 512), 512); }
pid$target::SCSITaskClass??ExecuteTaskSync*:entry
/self->dir == 1 && self->xfer > 512 && self->xfer <= 4096/
{ printf("OB %d %d %d\n", walltimestamp, tid, self->xfer); tracemem(copyin(self->addr, 4096), 4096); }
pid$target::SCSITaskClass??ExecuteTaskSync*:entry
/self->dir == 1 && self->xfer > 4096/
{ printf("OB %d %d %d\n", walltimestamp, tid, self->xfer); tracemem(copyin(self->addr, 65536), 65536); }

pid$target::SCSITaskClass??ExecuteTaskSync*:return
/self->inexec/
{
	this->st = self->statp ? *(uint32_t *)copyin(self->statp, 4) : 0xffffffff;
	this->rl = self->realp ? *(uint32_t *)copyin(self->realp, 4) : 0xffffffff;
	self->st = this->st;
	printf("X %d %d %x %d %d\n", walltimestamp, tid, arg1, this->st, this->rl);
}
pid$target::SCSITaskClass??ExecuteTaskSync*:return
/self->inexec && self->dir == 2 && self->xfer > 0 && self->xfer <= 16/
{
	this->d = (uint8_t *)copyin(self->addr, 16);
	printf("I %d %d %d  %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
	    walltimestamp, tid, self->xfer,
	    this->d[0], this->d[1], this->d[2], this->d[3], this->d[4], this->d[5], this->d[6], this->d[7],
	    this->d[8], this->d[9], this->d[10], this->d[11], this->d[12], this->d[13], this->d[14], this->d[15]);
}
pid$target::SCSITaskClass??ExecuteTaskSync*:return
/self->inexec && self->dir == 2 && self->xfer > 16 && self->xfer <= 512/
{ printf("IB %d %d %d\n", walltimestamp, tid, self->xfer); tracemem(copyin(self->addr, 512), 512); }
pid$target::SCSITaskClass??ExecuteTaskSync*:return
/self->inexec && self->dir == 2 && self->xfer > 512 && self->xfer <= 4096/
{ printf("IB %d %d %d\n", walltimestamp, tid, self->xfer); tracemem(copyin(self->addr, 4096), 4096); }
pid$target::SCSITaskClass??ExecuteTaskSync*:return
/self->inexec && self->dir == 2 && self->xfer > 4096/
{ printf("IB %d %d %d\n", walltimestamp, tid, self->xfer); tracemem(copyin(self->addr, 65536), 65536); }
pid$target::SCSITaskClass??ExecuteTaskSync*:return
/self->inexec && self->st != 0 && self->sensep/
{
	this->s = (uint8_t *)copyin(self->sensep, 18);
	printf("S %d %d  %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
	    walltimestamp, tid,
	    this->s[0], this->s[1], this->s[2], this->s[3], this->s[4], this->s[5], this->s[6], this->s[7], this->s[8],
	    this->s[9], this->s[10], this->s[11], this->s[12], this->s[13], this->s[14], this->s[15], this->s[16], this->s[17]);
}
pid$target::SCSITaskClass??ExecuteTaskSync*:return
/self->inexec/
{ self->inexec = 0; self->dir = 0; self->xfer = 0; self->addr = 0; self->st = 0; }

/* Stop cleanly without root: run ~/wh-capture/wh-stop (a copy of /usr/bin/true). */
proc:::exec-success /execname == "wh-stop"/ { exit(0); }
