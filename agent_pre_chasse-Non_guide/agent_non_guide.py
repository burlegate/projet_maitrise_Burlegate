from core_prechasse import parse_args, run_prechasse
if __name__ == '__main__':
    args=parse_args('Agent autonome non guidé de pré-chasse DNS')
    run_prechasse('non_guide', args.csv.expanduser().resolve(), args.raisonnement, args.max_output_tokens)
