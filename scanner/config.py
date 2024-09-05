import yaml
import os

def load_config(config_path='config.yaml'):
    try:
        with open(config_path, 'r') as config_file:
            config = yaml.safe_load(config_file)
        return config
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML configuration: {e}")
