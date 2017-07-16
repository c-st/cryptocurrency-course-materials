import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class TxHandler {
    private final UTXOPool pool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.pool = new UTXOPool(utxoPool);
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        final List<Transaction> validTxs = Arrays.stream(possibleTxs).filter(this::isValidTx).map(tx -> {
            // remove inputs (old)
            tx.getInputs().forEach(input -> {
                final UTXO oldUTXO = new UTXO(input.prevTxHash, input.outputIndex);
                this.pool.removeUTXO(oldUTXO);
            });

            // add outputs (new)
            tx.getOutputs().forEach(output -> {
                final int index = tx.getOutputs().indexOf(output);
                final UTXO newUTXO = new UTXO(tx.getHash(), index);
                this.pool.addUTXO(newUTXO, tx.getOutput(index));
            });

            return tx;
        }).collect(Collectors.toList());

        return validTxs.toArray(new Transaction[validTxs.size()]);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     * values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        final UTXOPool checkedUtxo = new UTXOPool();
        int inputSum = 0;

        for (int index = 0; index < tx.numInputs(); index++) {
            final Transaction.Input input = tx.getInput(index);
            final UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            if (!this.pool.contains(utxo)) {
                return false; //1
            }
            final Transaction.Output output = this.pool.getTxOutput(utxo);
            if (!Crypto.verifySignature(output.address, tx.getRawDataToSign(index), input.signature)) {
                return false; //2
            }
            if (checkedUtxo.contains(utxo)) {
                return false; //3
            }
            checkedUtxo.addUTXO(utxo, output);
            inputSum += output.value;
        }

        int outputSum = 0;
        for (final Transaction.Output output : tx.getOutputs()) {
            if (output.value < 0) {
                return false; //4 -> output values from output
            }
            outputSum += output.value;
        }

        return inputSum >= outputSum;
    }
}
