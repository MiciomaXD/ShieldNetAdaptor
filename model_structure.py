import torch
from very_simple_logger import *
from config import *
import pickle
from sklearn.preprocessing import StandardScaler

class Net(torch.nn.Module):
    """Model structure of ShieldNet"""
    def __init__(self):
        super(Net, self).__init__()
        self.model=torch.nn.Sequential(
            torch.nn.Linear(20, 512),
            torch.nn.ReLU(),
            torch.nn.Linear(512, 256),
            torch.nn.ReLU(),
            torch.nn.Linear(256, 128),
            torch.nn.Tanh(),
            torch.nn.Linear(128, 64),
            torch.nn.Tanh(),
            torch.nn.Linear(64, 2),
            torch.nn.LogSoftmax(dim=1)
            )

    def forward(self, x):
        return self.model(x)
"""
def init_weights(module):
        if isinstance(module, torch.nn.Linear):
            torch.nn.init.xavier_uniform_(module.weight)
            if module.bias is not None:
                module.bias.data.fill_(0.0001)

model = AttackNet()
model.apply(init_weights)
"""

class ShieldNet():
    """Wrapper of model pytorch class"""
    def __init__(self, model_path: str, scaler_path: str, logger: VerySimpleLogger):
        self.model = self.__load_momodel(model_path)
        self.scaler = self.__load_scaler(scaler_path)
        self.logger = logger

    def __load_scaler(self, path) -> StandardScaler:
        try:
            with open(path, 'rb') as file:
                return pickle.load(file)

        except Exception as e:
            self.logger.log(e.with_traceback(), Level.ERROR, APP_NAME_CORE + '_neural')
            raise

    def __load_momodel(self, path) -> Net:
        try:
            model = Net()
            model.load_state_dict(torch.load(path))
            model.eval()

            return model

        except Exception as e:
            self.logger.log(e.with_traceback(), Level.ERROR, APP_NAME_CORE + '_neural')
            raise

    def eval_input(self, input: torch.Tensor):
        """Pass a tensor to evaluate in the loaded model. Returns 
        the class index and the relative probability"""
        with torch.no_grad():
            logits = self.model(self.scaler.transform(input))
            true_logits = torch.exp(logits)
            prediction = torch.argmax(logits, dim=1)

            probability = torch.zeros(true_logits.shape[0], dtype=torch.float32)
            for i, p, l in enumerate(zip(prediction, true_logits)):
                probability[i] = l[p]

            return prediction, probability

