package org.ergoplatform.appkit.ergotool

import org.ergoplatform.wallet.Constants
import org.ergoplatform.wallet.secrets.ExtendedSecretKeySerializer
import org.ergoplatform.appkit.cli.AppContext
import org.ergoplatform.appkit.commands.{CmdParameter, NetworkPType, Cmd, SecretStringPType, NewPasswordInput, CmdDescriptor}
import org.ergoplatform.appkit.config.ErgoToolConfig
import org.ergoplatform.appkit.{JavaHelpers, NetworkType, Address, SecretString}
import org.ergoplatform.appkit.commands.PasswordInput
import org.ergoplatform.appkit.commands.DefaultParameterInput
import scorex.util.encode.Base16
import scorex.util.serialization.VLQByteBufferWriter
import scorex.util.ByteArrayBuilder


/** Given [[mnemonic]], [[mnemonicPass]] and [[network]] the command computes
  * the address of the given network type.
  *
  * The command do the following:<br>
  * 1) it uses (mnemonic, password) pair to generate master secret key (unambiguously for each such pair)<br>
  * 2) it extracts public key (pk) which corresponds to the generated secret key <br>
  * 3) it construct pay-to-public-key address for pk (see `org.ergoplatform.P2PKAddress`)<br>
  * 4) it prints the text representation (Base58 string) of P2PKAddress bytes.
  *
  * @param toolConf     configuration parameters to be used for operation
  * @param name         command name
  * @param network      [[NetworkType]] of the target network for which the address should be generated
  * @param mnemonic     secret phrase which is used to generate (private, public) key pair, of which
  *                     public key is used to generate the [[Address]]
  * @param mnemonicPass password which is used to additionally protect mnemonic
  * @see [[AddressCmd$]] descriptor of the `address` command
  */
case class AddressCmd
( toolConf: ErgoToolConfig,
  name: String, network: NetworkType, mnemonic: SecretString, mnemonicPass: SecretString)
  extends Cmd {
  override def run(ctx: AppContext): Unit = {

    val rootSecret = JavaHelpers.seedToMasterKey(mnemonic, mnemonicPass, false)
    val writer = new VLQByteBufferWriter(new ByteArrayBuilder())
    ExtendedSecretKeySerializer.serialize(rootSecret, writer)
    val keyBytes = writer.toBytes.slice(0, Constants.SecretKeyLength)
    ctx.console.println(s"Secret root: ${Base16.encode(keyBytes)}")

    // Let's use "m/44'/429'/0'/0/index" path (this path is compliant with EIP-3 which
    // is BIP-44 for Ergo)
    val path = JavaHelpers.eip3DerivationParent()
    val secretKey = rootSecret.derive(path)


    val writer2 = new VLQByteBufferWriter(new ByteArrayBuilder())
    ExtendedSecretKeySerializer.serialize(secretKey, writer2)
    val keyBytes2 = writer2.toBytes.slice(0, Constants.SecretKeyLength)
    ctx.console.println(s"Secret root /0: ${Base16.encode(keyBytes2)}")


    val address = Address.fromMnemonic(network, mnemonic, mnemonicPass, false)
    val address0 = Address.createEip3Address(0, network, mnemonic, mnemonicPass, false)
    val address1 = Address.createEip3Address(1, network, mnemonic, mnemonicPass, false)
    val address2 = Address.createEip3Address(2, network, mnemonic, mnemonicPass, false)
    ctx.console.println(s"Pre-EIP-3: ${address.toString}")
    ctx.console.println(s"Post-EIP-3 /0: ${address0.toString}")
    ctx.console.println(s"Post-EIP-3 /1: ${address1.toString}")
    ctx.console.println(s"Post-EIP-3 /2: ${address2.toString}")
  }
}

/** Descriptor and parser of the `address` command. */
object AddressCmd extends CmdDescriptor(
  name = "address", cmdParamSyntax = "testnet|mainnet",
  description = "return address for a given mnemonic and password pair") {

  override val parameters: Seq[CmdParameter] = Array(
    CmdParameter("network", NetworkPType,
      "[[NetworkType]] of the target network for which the address should be generated"),
    CmdParameter("mnemonic", "Mnemonic", SecretStringPType,
      """secret phrase which is used to generate (private, public) key pair, of which
        |public key is used to generate the [[Address]]""".stripMargin, None,
        Some(DefaultParameterInput), None),
    CmdParameter("mnemonicPass", "Mnemonic password", SecretStringPType,
      "password which is used to additionally protect mnemonic", None,
      Some(PasswordInput), None)
  )

  override def createCmd(ctx: AppContext): Cmd = {
    val Seq(networkType: NetworkType, mnemonic: SecretString, mnemonicPass: SecretString) = ctx.cmdParameters
    AddressCmd(ctx.toolConf, name, networkType, mnemonic, mnemonicPass)
  }
}