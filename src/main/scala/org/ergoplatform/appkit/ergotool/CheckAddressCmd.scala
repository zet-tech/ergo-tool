package org.ergoplatform.appkit.ergotool

import org.ergoplatform.appkit.cli.AppContext
import org.ergoplatform.appkit.commands.{CmdParameter, NetworkPType, AddressPType, PasswordInput, Cmd, SecretStringPType, CmdDescriptor}
import org.ergoplatform.appkit.config.ErgoToolConfig
import org.ergoplatform.appkit.{NetworkType, Address, SecretString}
import org.ergoplatform.appkit.commands.NewPasswordInput
import org.ergoplatform.appkit.commands.DefaultParameterInput

/** Given [[network]], [[mnemonic]], [[mnemonicPass]] and [[address]] checks that the address
  * belongs to the given network and corresponds to the given mnemonic and mnemonic password.
  *
  * Steps:<br/>
  * 1) The network, mnemonic and mnemonicPass parameters are used to compute new address (see [[AddressCmd]])<br/>
  * 2) if computed address equals to the given address then print `Ok`
  *    otherwise print `Error`
  *
  * @param network      [[NetworkType]] of the target network for which the address should be checked
  * @param mnemonic     secret phrase which is used to generate (private, public) key pair, of which
  *                     public key is used to generate the [[Address]]
  * @param mnemonicPass password which is used to additionally protect mnemonic
  * @param address      address to check
  */
case class CheckAddressCmd(
    toolConf: ErgoToolConfig,
    name: String,
    network: NetworkType,
    mnemonic: SecretString,
    mnemonicPass: SecretString,
    address: Address) extends Cmd {

  override def run(ctx: AppContext): Unit = {
    if (network != address.getNetworkType)
      error(s"Network type of the address ${address.getNetworkType} don't match expected $network")
    val computedAddress = Address.fromMnemonic(network, mnemonic, mnemonicPass, false)
    val computedNetwork = computedAddress.getNetworkType
    val okNetwork = computedNetwork == network
    val res = if (okNetwork && computedAddress == address) "Ok" else s"Error"
    ctx.console.print(res)
  }

}

object CheckAddressCmd extends CmdDescriptor(
  name = "checkAddress", cmdParamSyntax = "testnet|mainnet <address>",
  description = "Check the given mnemonic and password pair correspond to the given address") {

  override val parameters: Seq[CmdParameter] = Array(
    CmdParameter("network", NetworkPType,
      "[[NetworkType]] of the target network for which the address should be generated"),
    CmdParameter("mnemonic", "Mnemonic", SecretStringPType,
      """secret phrase which is used to generate (private, public) key pair, of which
       |public key is used to generate the [[Address]]""".stripMargin, None,
       Some(DefaultParameterInput), None),
    CmdParameter("mnemonicPass", "Mnemonic password", SecretStringPType,
      "password which is used to additionally protect mnemonic", None,
      Some(PasswordInput), None),
    CmdParameter("address", AddressPType, "address to check")
  )

  override def createCmd(ctx: AppContext): Cmd = {
    val Seq(
      networkType: NetworkType,
      mnemonic: SecretString,
      mnemonicPass: SecretString,
      address: Address) = ctx.cmdParameters

    CheckAddressCmd(ctx.toolConf, name, networkType, mnemonic, mnemonicPass, address)
  }
}