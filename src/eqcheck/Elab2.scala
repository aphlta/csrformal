package eqcheck

import chisel3.RawModule
import circt.stage.ChiselStage
import org.chipsalliance.cde.config.Parameters

/** 最小精化 harness：把单个 CSR 子模块当作 top 精化出 CHIRRTL。
  *
  * 为什么不精化整核：目标模块（CSRPermitModule / TrapHandleModule /
  * InterruptFilter）都是普通的 `Module`，可以独立实例化，精化只需秒级。
  * 只有 trait 内的匿名 mixin 才必须走「精化 NewCSR + 切片」的贵路径。
  */
object Elab2 {
  private lazy val params: Parameters = {
    val (cfg, _, _) = top.ArgParser.parse(Array("--config", "MinimalConfig"))
    cfg.alterPartial { case xiangshan.XSCoreParamsKey => cfg(xiangshan.XSTileKey).head }
  }

  def build(name: String): RawModule = {
    implicit val p: Parameters = params
    name match {
      case "CSRPermitModule"  => new xiangshan.backend.fu.NewCSR.CSRPermitModule
      case "TrapHandleModule" => new xiangshan.backend.fu.NewCSR.TrapHandleModule
      case "InterruptFilter"  => new xiangshan.backend.fu.NewCSR.InterruptFilter
      case "MLevelPermitModule"       => new xiangshan.backend.fu.NewCSR.MLevelPermitModule
      case "SLevelPermitModule"       => new xiangshan.backend.fu.NewCSR.SLevelPermitModule
      case "PrivilegePermitModule"    => new xiangshan.backend.fu.NewCSR.PrivilegePermitModule
      case "VirtualLevelPermitModule" => new xiangshan.backend.fu.NewCSR.VirtualLevelPermitModule
      case "XRetPermitModule"         => new xiangshan.backend.fu.NewCSR.XRetPermitModule
      case "NewCSR"           => new xiangshan.backend.fu.NewCSR.NewCSR
      case other              => throw new IllegalArgumentException(s"unknown module: $other")
    }
  }

  def main(args: Array[String]): Unit = {
    val fir = ChiselStage.emitCHIRRTL(build(args(0)))
    val w = new java.io.PrintWriter(args(1))
    try w.write(fir) finally w.close()
    System.err.println(s"[elab] ${args(0)} -> ${args(1)} (${fir.length} chars)")
  }
}
